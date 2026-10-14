# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# shared/vault.py
#
# Glue between the vault policy core (shared/vault_policy.py) and the rest of
# the firmware. Per the gameplans this module intentionally holds ONLY:
#   - feature-on detection for vault mode (settings key 'vault')
#   - the relevance check over a candidate PSBT
#   - the spend-path view builder consumed by vault_policy.VaultPolicy
#   - the append-only vault signing ledger
#
# The rule layer stays in vault_policy.py; signature math stays in auth.py.
# This file gates reachability of the existing sign step and nothing more.
#
# Host-testable: python3 testing/test_vault.py
#
# pyright: reportMissingImports=false

from vault_policy import VaultPolicy, VaultViolation, leaf_hash, lattice_root

try:
    from ubinascii import hexlify as _hexlify, unhexlify as _unhexlify
except ImportError:
    from binascii import hexlify as _hexlify, unhexlify as _unhexlify

VAULT_LOG = 'vault.log'


def _cfg():
    try:
        from glob import settings
        return settings.get('vault') or {}
    except Exception:
        return {}


def is_enabled():
    # Vault mode active iff operator enrolled a policy and flipped it on.
    try:
        return bool(_cfg().get('enabled'))
    except Exception:
        return False


def is_strict():
    # Dedicated-signer posture: refuse EVERY non-vault spend outright.
    try:
        return bool(_cfg().get('strict'))
    except Exception:
        return False


def _h2b(x):
    return _unhexlify(x) if x else None


def _iter_input_utxos(psbt):
    # Yield (spk, value) for each input's spent output. Two shapes:
    #  - real firmware psbtObject: utxo/witness_utxo are (pos,len) proxies
    #    into the PSBT file, so recover the CTxOut via input.get_utxo(idx)
    #    (which prefers the full non-witness utxo when present)
    #  - host-test fakes: duck-typed .utxo objects.
    # Inputs with no utxo info are skipped here; view_from_psbt refuses
    # them instead (this fn only powers the relevance sniff).
    if hasattr(psbt, 'input_iter') and hasattr(psbt, 'output_iter'):
        for idx, txin in psbt.input_iter():
            inp = psbt.inputs[idx]
            if not (getattr(inp, 'utxo', None) or getattr(inp, 'witness_utxo', None)):
                continue
            u = inp.get_utxo(idx)
            yield bytes(u.scriptPubKey), u.nValue
    else:
        for inp in psbt.inputs:
            u = getattr(inp, 'utxo', None)
            if u is None:
                continue
            yield bytes(u.scriptPubKey), getattr(u, 'nValue', None)


def check_relevance(psbt, cfg):
    # A tx must pass policy iff any input spends the vault or the sink.
    # Never raises: odd shapes - including a missing/unparseable cfg -
    # are treated as relevant, so the policy layer judges (and refuses)
    # them (fail-closed). A cfg w/o sv_hash/spk_e cannot match anything
    # => not relevant.
    try:
        cfg = cfg or {}
        spk_v, spk_e = _h2b(cfg.get('sv_hash')), _h2b(cfg.get('spk_e'))
        if not (spk_v or spk_e):
            return False
        for spk, val in _iter_input_utxos(psbt):
            if (spk_v and spk == spk_v) \
                    or (spk_e and spk == spk_e):
                return True
    except Exception:
        return True     # odd shape: treat as relevant, policy will judge
    return False


def view_from_psbt(psbt):
    # Build the policy view from a live PSBT. Fail-closed: raise
    # VaultViolation whenever a needed fact is uncollectable so the caller
    # refuses instead of approving on partial information.
    view = {'lock_time': getattr(psbt, 'lock_time', 0), 'inputs': [], 'outputs': []}
    if hasattr(psbt, 'input_iter') and hasattr(psbt, 'output_iter'):
        # real firmware psbtObject: nSequence lives in the unsigned tx
        # (input_iter -> CTxIn), utxos are file proxies, outputs stream
        # via output_iter(); part_sigs is a {pubkey: sig} dict.
        seqs = dict((idx, txin.nSequence) for idx, txin in psbt.input_iter())
        for idx, inp in enumerate(psbt.inputs):
            if not (getattr(inp, 'utxo', None) or getattr(inp, 'witness_utxo', None)):
                raise VaultViolation('missing witness_utxo')
            u = inp.get_utxo(idx)
            part = getattr(inp, 'part_sigs', None)
            view['inputs'].append({
                'spk': bytes(u.scriptPubKey),
                'value': u.nValue,
                'sequence': seqs.get(idx),
                'part_sigs': list(part) if part else [],
            })
        for idx, txo in psbt.output_iter():
            # carry psbt.outputs[idx].is_change (set by consider_outputs
            # in the auth.py flow) so P1 can refuse contradictory
            # "pinned spk_e but marked change" emergencies
            out = psbt.outputs[idx] if psbt.outputs \
                and idx < len(psbt.outputs) else None
            view['outputs'].append({
                'spk': bytes(txo.scriptPubKey),
                'value': txo.nValue,
                'is_change': bool(out and getattr(out, 'is_change', None)),
            })
        return view
    for inp in psbt.inputs:
        u = getattr(inp, 'utxo', None)
        if u is None:
            raise VaultViolation('missing witness_utxo')
        part = getattr(inp, 'part_sigs', None)
        view['inputs'].append({
            'spk': bytes(u.scriptPubKey),
            'value': getattr(u, 'nValue', None),
            'sequence': getattr(inp, 'sequence', None),
            'part_sigs': list(part) if part else [],
        })
    for o in psbt.outputs:
        view['outputs'].append({
            'spk': bytes(o.scriptPubKey),
            'value': getattr(o, 'nValue', None),
            'is_change': bool(getattr(o, 'is_change', None)),
        })
    return view


def could_sign(cfg, psbt):
    # Policy entry used by auth.py. Returns (approve, msg); never raises:
    # failures collapse to (False, reason).
    try:
        desc = VaultPolicy(cfg).check(view_from_psbt(psbt))
        return True, desc
    except VaultViolation as e:
        return False, str(e)
    except Exception as e:
        return False, 'vault policy error: %s' % (e,)


def vault_log(msg, logfile=VAULT_LOG):
    # Append-only ledger on internal flash. Never raises: logging must not be
    # able to break signing; a refusal is still surfaced via UX.
    try:
        try:
            y = str(__import__('utime').ticks_ms())
        except Exception:
            try:
                y = str(__import__('time').time())
            except Exception:
                y = '?'
        line = '[%s] %s\n' % (y, msg)
        try:
            with open(logfile, 'a') as fd:
                fd.write(line)
        except OSError:
            with open(logfile, 'w') as fd:
                fd.write(line)
    except Exception:
        pass


def validate_cfg(cfg):
    # Minimum enrollable policy shape. Returns (ok, msg); never raises.
    if not cfg:
        return False, 'no policy enrolled'
    for k in ('sv_hash', 'spk_e', 'k1_pubkey', 'exit_spk'):
        if not cfg.get(k):
            return False, 'missing %s' % k
    try:
        VaultPolicy(cfg)
    except Exception as e:
        return False, 'bad policy: %s' % (e,)
    return True, 'ok'


def save_cfg(cfg):
    # Persist the vault settings dict under settings key 'vault'.
    from glob import settings
    settings.set('vault', cfg)


def wipe():
    # Remove the vault policy entirely. Cannot be undone.
    try:
        from glob import settings
        settings.remove_key('vault')
    except Exception:
        pass


def set_enabled(on):
    # Flip vault mode. Enabling is refused until the enrolled policy
    # passes validate_cfg. Returns (ok, msg); never raises.
    cfg = _cfg()
    if on:
        ok, msg = validate_cfg(cfg)
        if not ok:
            return False, msg
    cfg['enabled'] = 1 if on else 0
    try:
        save_cfg(cfg)
    except Exception as e:
        return False, 'cannot save: %s' % (e,)
    vault_log('CFG %s' % ('enabled' if on else 'disabled'))
    return True, 'ok'


def _b2h(b):
    return str(_hexlify(bytes(b)), 'ascii')


def enroll_lattice(cfg, psbt_iter):
    # Lattice enrollment, T5 steps 3-4 of the commitment plan:
    #   1. every member is shape-validated against the policy (full-batch
    #      check at enrollment; any failure raises with the leaf index)
    #   2. leaves are hashed from .txn (the raw global unsigned-tx bytes)
    #      and streamed into the Merkle carry-tree
    # Returns (root_hex, count). NEVER writes settings: the caller must
    # display the root, get user confirmation vs the host UI, and only
    # then call store_lattice.
    pol = VaultPolicy(cfg)

    def leaves():
        for i, psbt in enumerate(psbt_iter):
            try:
                pol.check(view_from_psbt(psbt))
            except VaultViolation as e:
                raise VaultViolation('lattice[%d]: %s' % (i, e))
            tx = getattr(psbt, 'txn', None)
            if not tx:
                raise VaultViolation('lattice[%d]: missing unsigned tx' % i)
            if not isinstance(tx, (bytes, bytearray)):
                # real psbtObject: .txn is a (pos,len) proxy into the file
                tx = psbt.get(tx)
            yield leaf_hash(i, tx)

    root, count = lattice_root(leaves())
    return _b2h(root), count


def store_lattice(root_hex, count):
    # T5 step 6: persist the commitment. Call ONLY after the user has
    # confirmed device-root == host-root on screen.
    cfg = _cfg()
    cfg['lattice_root'] = root_hex
    cfg['lattice_count'] = count
    save_cfg(cfg)
    vault_log('CFG lattice %d leaves' % count)


class VaultMode:
    # Marker/handle class, CCCFeature style, so auth.py call sites read like
    # the existing feature blocks. All methods class-level.

    @classmethod
    def is_enabled(cls):
        return is_enabled()

    @classmethod
    def could_sign(cls, psbt):
        # Full decision path for the signing choke point: relevance gate,
        # policy evaluation, strict-mode handling, ledger write.
        cfg = _cfg()
        if not check_relevance(psbt, cfg):
            if is_strict():
                vault_log('REFUSE non-vault spend (strict)')
                return False, 'strict vault signer refuses non-vault spend'
            return True, 'not vault-relevant'
        appr, msg = could_sign(cfg, psbt)
        if not appr:
            vault_log('REFUSE %s' % msg)
            return False, msg
        vault_log('APPR %s' % msg)
        return True, msg

# EOF
