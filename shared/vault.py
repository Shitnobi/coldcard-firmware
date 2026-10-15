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

# Implementation version of the vault SIGNING path, stamped into the cfg
# at every save and into every approval ledger line, so vault.log records
# which implementation produced each entry:
#   1 = pre-remediation: stock M/N heuristics (V-01/V-02 misparses)
#   2 = remediated: vault_signing recognition + role-based completion +
#       policy-gate approval record bound to the signature (plan 1.x),
#       strict-DER/low-S/SIGHASH_ALL partial-sig verification (V-03/V-04),
#       full-UTXO requirement (V-05), strict ccc ratchet predicate (V-06)
#   3 = validity audit #2 round: ladders require nVersion >= 2 (W-01) and
#       full UTXOs (W-02); dust/min-relay standardness floors on all
#       classes (W-03/W-04); sv_hash != spk_e at enrollment (W-05)
#   4 = consistency audit #3 round: script parsers refuse duplicate
#       pubkeys (X-01, quorum collapse); recognize() cross-checks the
#       script's N against the enrolled cfg n (X-02, consensus-valid
#       ladders); set_n refuses edits while vault mode is enabled and
#       the strict posture is surfaced at enrollment + policy viewer
#       (X-03)
VAULT_IMPL_VERSION = 4


def _cfg():
    # Always returns a dict: a corrupt (non-dict) stored value must not
    # crash menu/signing code with AttributeError halfway through.
    # Master-scoped read: during a tmp-seed session the plain get would
    # read the (empty) tmp scope and silently turn the policy gate OFF;
    # master_get reads the master seed's copy instead ('vault' is in
    # nvstore MASTER_FIELDS, captured by leaving_master_seed).
    try:
        from glob import settings
        v = settings.master_get('vault')
        return v if isinstance(v, dict) else {}
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
    # Yield (spk, value, verified) for each input's spent output. Two shapes:
    #  - real firmware psbtObject: utxo/witness_utxo are (pos,len) proxies
    #    into the PSBT file, so recover the CTxOut via input.get_utxo(
    #    txin.prevout.n) (which prefers the full non-witness utxo when
    #    present); the spent coin sits at the PREVOUT vout, never at the
    #    input's position
    #  - host-test fakes: duck-typed .utxo objects.
    # Inputs with no utxo info are skipped here; view_from_psbt refuses
    # them instead (this fn only powers the relevance sniff).
    #
    # V-05 fix, relevance side: 'verified' marks whether the input's spk is
    # trustworthy: full utxo (txid-cross-checked upstream in validate()) is
    # trusted; a witness_utxo-only input is trusted only if its witness
    # script hashes to the claimed spk. An UNVERIFIABLE vault-shaped claim
    # (witness-utxo-only, script/spk disagreement, or no script at all)
    # yields verified=False so check_relevance treats it as relevant and
    # the fail-closed policy layer judges (and refuses) it - a vault coin
    # can no longer be hidden from the relevance gate by asserting a
    # foreign spk or omitting the witness script.
    if hasattr(psbt, 'input_iter') and hasattr(psbt, 'output_iter'):
        for idx, txin in psbt.input_iter():
            inp = psbt.inputs[idx]
            if not (getattr(inp, 'utxo', None) or getattr(inp, 'witness_utxo', None)):
                # section 3.2: surface (spk=None) instead of silently
                # skipping - check_relevance treats it as relevant and
                # the policy layer refuses it loudly
                yield None, None, False
                continue
            u = inp.get_utxo(txin.prevout.n)
            yield bytes(u.scriptPubKey), u.nValue, _spk_verified(inp)
    else:
        for inp in psbt.inputs:
            u = getattr(inp, 'utxo', None)
            if u is None:
                continue
            yield bytes(u.scriptPubKey), getattr(u, 'nValue', None), True


def _spk_verified(inp):
    # Is this input's claimed spk trustworthy for relevance purposes?
    # - full (non-witness) utxo present: yes (txid checked upstream)
    # - witness_utxo only: yes iff sha256(witness_script) == spk[2:34]
    # - anything else: no
    if getattr(inp, 'utxo', None):
        return True
    ws = getattr(inp, 'witness_script', None)
    if not ws:
        return False
    try:
        from uhashlib import sha256
    except ImportError:
        from hashlib import sha256
    try:
        script = inp.get(ws)
        # read the witness utxo spk (idx-independent: the (pos,len) proxy
        # points at one CTxOut)
        u = inp.get_utxo(0)
        return sha256(script).digest() == bytes(u.scriptPubKey)[2:34]
    except Exception:
        return False


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
        for spk, val, verified in _iter_input_utxos(psbt):
            if spk is None:
                # input with no utxo data at all (section 3.2): could be
                # a hidden vault coin - treat as relevant so the policy
                # layer (view_from_psbt) refuses it loudly instead of the
                # relevance sniff silently skipping it
                return True
            if (spk_v and spk == spk_v) \
                    or (spk_e and spk == spk_e):
                return True
            if not verified:
                # unverifiable spk claim: could be a hidden vault coin,
                # fail closed - let the policy layer judge it
                return True
    except Exception as e:
        # odd shape: treat as relevant, policy will judge - but log it so
        # a misclassification is auditable in vault.log (section 3.2)
        try:
            vault_log('relevance: odd shape treated as relevant: %s' % e)
        except Exception:
            pass
        return True
    return False


def is_vault_psbt(psbt, cfg):
    # Section 3.1 (V-06 fix): STRICT fail-closed predicate for the CCC
    # velocity-ratchet skip. Unlike check_relevance (a refusal-gate
    # sniff, where odd shapes must count as relevant so the policy layer
    # refuses them), this returns True ONLY for provably-vault PSBTs:
    #   (a) the cfg parses and has a enrolled script hash,
    #   (b) EVERY input carries verifiable utxo data (full utxo, or a
    #       witness utxo whose witness script hashes to the claimed spk),
    #   (c) at least one input's spk matches the enrolled S_v/S_e hash
    #       AND its witness script structurally parses as that kind.
    # Any doubt => False => the velocity ratchet still applies. The
    # audit's V-06 was the fail-open inverse: check_relevance's
    # exception path returned True for "odd shapes", so a crafted PSBT
    # could skip the ratchet while the vault gate (if mode was off, or
    # the psbt only looked vault-ish) never judged it.
    try:
        spk_v = _h2b((cfg or {}).get('sv_hash'))
        spk_e = _h2b((cfg or {}).get('spk_e'))
        if not (spk_v or spk_e):
            return False
        import vault_signing
        seen_vault = False
        for idx, txi in psbt.input_iter():
            inp = psbt.inputs[idx]
            if not (getattr(inp, 'utxo', None) or
                    getattr(inp, 'witness_utxo', None)):
                return False
            if not _spk_verified(inp):
                return False
            spk = bytes(inp.get_utxo(txi.prevout.n).scriptPubKey)
            if not (spk == spk_v or spk == spk_e):
                continue
            ws = getattr(inp, 'witness_script', None)
            if not ws:
                return False
            if isinstance(ws, (tuple, list)):
                script = inp.get(ws)
            else:
                script = ws
            if vault_signing.recognize(script, cfg) != \
                    ('sv' if spk == spk_v else 'se'):
                return False
            seen_vault = True
        return seen_vault
    except Exception:
        return False


def view_from_psbt(psbt):
    # Build the policy view from a live PSBT. Fail-closed: raise
    # VaultViolation whenever a needed fact is uncollectable so the caller
    # refuses instead of approving on partial information.
    view = {'lock_time': getattr(psbt, 'lock_time', 0), 'inputs': [], 'outputs': []}
    # W-01 (validity audit #2): carry the global tx nVersion so the
    # policy layer can enforce BIP-68/112's version >= 2 for CSV ladders.
    # Unknown (host-test fakes without the fact) stays None => the ladder
    # checker fails closed.
    view['tx_version'] = getattr(psbt, 'txn_version', None)
    if hasattr(psbt, 'input_iter') and hasattr(psbt, 'output_iter'):
        # real firmware psbtObject: nSequence lives in the unsigned tx
        # (input_iter -> CTxIn), utxos are file proxies, outputs stream
        # via output_iter(); part_sigs is a {pubkey: sig} dict.
        seqs = dict((idx, txin.nSequence) for idx, txin in psbt.input_iter())
        # spent-output index is the PREVOUT vout, never the input position
        # (get_utxo indexes the funding tx's outputs) - a vault coin at
        # vout != input idx must not read a sibling output's spk/amount
        vouts = dict((idx, txin.prevout.n) for idx, txin in psbt.input_iter())
        for idx, inp in enumerate(psbt.inputs):
            if not (getattr(inp, 'utxo', None) or getattr(inp, 'witness_utxo', None)):
                raise VaultViolation('missing witness_utxo')
            u = inp.get_utxo(vouts[idx])
            part = getattr(inp, 'part_sigs', None)
            # V-05 fix: mark amount provenance; a witness_utxo-only input
            # is never txid-validated upstream, so fee-bearing classes
            # (P1/P3) refuse it (see VaultPolicy._require_full_utxo).
            # Also fail closed when the claimed spk disagrees with the
            # witness script hash (relevance-side check mirrors this).
            utxo_full = bool(getattr(inp, 'utxo', None))
            if not utxo_full:
                ws = getattr(inp, 'witness_script', None)
                if not ws:
                    raise VaultViolation('witness-utxo input missing '
                                         'witness script')
                if not _spk_verified(inp):
                    raise VaultViolation('witness_utxo spk does not match '
                                         'witness script')
            # V-03/V-04 fix material: carry the raw sig bytes (for sighash
            # typing + ECDSA verification in could_sign) and the PSBT-
            # declared sighash type for this input
            sig_data, sighashes = {}, []
            for pk, ref in (part or {}).items():
                sig = inp.get(ref) if isinstance(ref, (tuple, list)) else ref
                sig_data[bytes(pk)] = bytes(sig)
                if len(sig):
                    sighashes.append(sig[-1])
            sht = getattr(inp, 'sighash', None)
            if sht is None:
                sht = 1     # implicit SIGHASH_ALL per BIP-174
            view['inputs'].append({
                'spk': bytes(u.scriptPubKey),
                'value': u.nValue,
                'sequence': seqs.get(idx),
                'part_sigs': list(part) if part else [],
                'sig_data': sig_data,
                'sighashes': sighashes,
                'sighash_type': sht,
                'utxo_full': utxo_full,
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
        view = view_from_psbt(psbt)
        # V-03 fix: cryptographically verify every partial signature on
        # vault-relevant inputs (DER shape, low-S, SIGHASH_ALL byte, and
        # the ECDSA check against the BIP-143 digest of THIS transaction).
        # Presence-only checking (the audit's V-03) let garbage blobs pass
        # policy; finalize() would then ship them in the final witness.
        _verify_vault_partials(cfg, psbt, view)
        desc = VaultPolicy(cfg).check(view)
        return True, desc
    except VaultViolation as e:
        return False, str(e)
    except Exception as e:
        return False, 'vault policy error: %s' % (e,)


def _verify_vault_partials(cfg, psbt, view):
    # Real-psbtObject shape only: host-test fakes carry no BIP-143
    # machinery (their part_sigs are pubkey lists; the pure policy layer
    # covers them). For each vault/sink-relevant input, verify every
    # partial signature. Raises VaultViolation; returns silently when
    # nothing to check.
    if not hasattr(psbt, 'make_txn_segwit_sighash'):
        return
    pol = VaultPolicy(cfg)
    relevant = [pol.spk_v, pol.spk_e]
    import vault_signing as vs
    for idx, txi in psbt.input_iter():
        inp = psbt.inputs[idx]
        if not getattr(inp, 'has_utxo', lambda: False)():
            continue
        u = inp.get_utxo(txi.prevout.n)
        if bytes(u.scriptPubKey) not in relevant:
            continue
        ws = getattr(inp, 'witness_script', None)
        if not ws:
            raise VaultViolation('vault input %d: missing witness script' % idx)
        vs.verify_input_sigs(psbt, idx, inp, txi, inp.get(ws))


def _approval_record(cfg, psbt, view, desc):
    # Plan section 1.5: in-memory record of exactly what the policy gate
    # approved. psbtObject.sign_it() refuses (fail-closed) to sign a vault
    # input unless this record is present and still matches the tx facts,
    # closing the semantic gap between "what the gate saw" and "what the
    # signer signs" (the PSRAM re-hash already pins the raw bytes; this
    # pins the policy decision).
    pol = VaultPolicy(cfg)
    kinds = []
    for i in view['inputs']:
        spk = bytes(i['spk'])
        kinds.append('sv' if spk == pol.spk_v else
                     ('se' if spk == pol.spk_e else None))
    # branch selector for ladder scripts: derived from the APPROVED class,
    # never from PSBT metadata - the device constructs what it approved
    selector = None
    if any(k == 'sv' for k in kinds):
        selector = 1 if desc.startswith('ladder') else 0
    outpoints = None
    try:
        outpoints = [(txi.prevout.hash, txi.prevout.n)
                     for _, txi in psbt.input_iter()]
    except Exception:
        pass          # host-test fakes without input_iter
    try:
        out_spks = [bytes(o['spk']) for o in view['outputs']]
        fee = (sum(i['value'] for i in view['inputs']) -
               sum(o['value'] for o in view['outputs']))
    except Exception:
        out_spks, fee = None, None
    return {
        'class': desc,
        'kinds': kinds,
        'selector': selector,
        'outpoints': outpoints,
        'out_spks': out_spks,
        'fee': fee,
        'sighashes': [i.get('sighash_type') or 1 for i in view['inputs']],
    }


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
    # - master-scoped: the vault is a DEVICE-level policy (the Coldcard
    #   is the dedicated co-signer) - it must survive seed switches and
    #   stay enforced during tmp-seed sessions, like ccc/sssp policy
    #   settings. master_set writes the master seed's store.
    # - immediate save: nvstore.set() (=put) only marks the store dirty
    #   with a 250ms deferred write, so power loss in that window would
    #   silently lose the change. master_set always saves immediately.
    # - section 3.4: stamp the first-seen enrollment time and log the
    #   policy hashes so the enrollment is auditable in vault.log and
    #   displayable in the policy viewer.
    cfg = dict(cfg)
    cfg['vault_impl_version'] = VAULT_IMPL_VERSION
    if not cfg.get('enrolled_ts'):
        try:
            import utime
            cfg['enrolled_ts'] = int(utime.time())
        except Exception:
            try:
                import time
                cfg['enrolled_ts'] = int(time.time())
            except Exception:
                pass
    from glob import settings
    settings.master_set('vault', cfg)
    vault_log('CFG saved: n=%s f0_max=%s sv_hash=%s... spk_e=%s... '
              'exit_spk=%s...%s'
              % (cfg.get('n'), cfg.get('f0_max'),
                 (cfg.get('sv_hash') or '')[:16],
                 (cfg.get('spk_e') or '')[:16],
                 (cfg.get('exit_spk') or '')[:16],
                 ' ts=%s' % cfg['enrolled_ts'] if cfg.get('enrolled_ts') else ''))


def human_ts(ts):
    # Format the 'enrolled_ts' epoch stamp for the policy viewer
    # (vault_menu 'Show Policy'). Host-testable: on the unix build
    # utime.time()/gmtime exist via the time module shim.
    try:
        import utime
        t = utime.gmtime(int(ts))
    except Exception:
        import time
        t = time.gmtime(int(ts))
    return '%d-%02d-%02d %02d:%02d UTC' % (t[0], t[1], t[2], t[3], t[4])


def wipe():
    # Remove the vault policy entirely. Cannot be undone.
    # Returns (ok, msg); never raises: a policy that survives a
    # "successful" wipe keeps constraining signing, so the menu must be
    # able to report the failure instead of a silently swallowed one.
    # Master-scoped: in a tmp-seed session, removing from the current
    # (tmp) scope would leave the master copy enforced - remove from
    # the master store itself (the menu's is_not_tmp predicate normally
    # prevents reaching this in tmp mode, but be correct anyway).
    try:
        from glob import settings
        from nvstore import SettingsObject
        if SettingsObject.master_nvram_key:
            master = SettingsObject(nvram_key=SettingsObject.master_nvram_key)
            master.load()
            master.remove_key('vault')
            master.save()
            SettingsObject.master_sv_data.pop('vault', None)
        else:
            settings.remove_key('vault')
            settings.save()
    except Exception as e:
        return False, 'cannot wipe: %s' % (e,)
    return True, 'ok'


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


def _iter_outpoints(psbt):
    # Yield (hash, vout) for every tx input, both PSBT shapes:
    #  - real firmware psbtObject: input_iter() -> CTxIn; prevout.hash is
    #    the uint256 int from deser_uint256 = internal byte order
    #  - host-test fakes: duck-typed .prevout with .hash (bytes in
    #    internal byte order) and .n
    # Raises VaultViolation when a fake input carries no prevout (the
    # binding check must fail closed, not skip silently).
    if hasattr(psbt, 'input_iter') and hasattr(psbt, 'output_iter'):
        for idx, txin in psbt.input_iter():
            yield txin.prevout.hash, txin.prevout.n
    else:
        for inp in psbt.inputs:
            po = getattr(inp, 'prevout', None)
            if po is None:
                raise VaultViolation('missing prevout')
            yield po.hash, po.n


def check_lattice_binding(manifest, psbt_iter, cfg=None):
    # Manifest cross-check (Decision B, choice b). hostapp/vault_tree.py
    # writes manifest.json next to the leaf PSBTs, declaring the deposit
    # outpoint every leaf must spend (deposit_txid = DISPLAY-order hex,
    # vault_vout), the leaf count, and the cfg the host built against.
    # Before the batch is accepted we verify the parsed leaves actually
    # spend that outpoint, that the count matches, and (when cfg is
    # given) that the enrolled policy agrees with the manifest's cfg on
    # every policy-defining field - so a leaf set and manifest that
    # disagree (host bug, or either file swapped on the card) is refused
    # loudly instead of silently committing the wrong thing.
    #
    # TRUST BOUNDARY: the manifest is host-authored. This check catches
    # only INCONSISTENT lying (leaves vs manifest); a host that builds
    # bad leaves and an honest-looking manifest passes. The real
    # commitments remain the device-side policy check and the
    # device-computed Merkle root compared by the human against the host
    # UI. See docs/vault_progress.md session (h) for the unchosen
    # stronger designs.
    #
    # Raises VaultViolation on any mismatch. Never writes settings.
    manifest = manifest or {}
    want_txid = _h2b(manifest.get('deposit_txid'))
    want_vout = manifest.get('vault_vout')
    if not want_txid or len(want_txid) != 32 or want_vout is None:
        raise VaultViolation('manifest: missing or invalid '
                             'deposit_txid / vault_vout')
    want_txid = bytes(reversed(want_txid))    # display -> internal order
    psbts = list(psbt_iter)
    want_count = manifest.get('lattice_count')
    if want_count is not None and len(psbts) != want_count:
        raise VaultViolation('manifest: %d leaves picked but declares '
                             'lattice_count=%d' % (len(psbts), want_count))
    for i, psbt in enumerate(psbts):
        for j, (h, n) in enumerate(_iter_outpoints(psbt)):
            hb = h.to_bytes(32, 'little') if isinstance(h, int) else bytes(h)
            if hb != want_txid or n != want_vout:
                raise VaultViolation('lattice[%d] input %d does not spend '
                                     'the deposit outpoint declared in '
                                     'manifest' % (i, j))
    if cfg is not None:
        mc = manifest.get('cfg')
        if isinstance(mc, dict):
            for k in ('n', 'sv_hash', 'spk_e', 'k1_pubkey', 'f0_max',
                      'exit_spk'):
                if k in mc and str(mc[k]) != str(cfg.get(k)):
                    raise VaultViolation('manifest: cfg %s = %r but device '
                                         'policy has %r' % (k, mc[k],
                                                            cfg.get(k)))


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
        # section 1.5: leave the approval record on this object for
        # sign_it() to bind the signature to (see psbtObject.
        # _check_vault_approval); without a record, sign_it refuses
        # vault inputs fail-closed.
        try:
            rec = _approval_record(cfg, psbt, view_from_psbt(psbt), msg)
            psbt.vault_approval = rec
            vault_log('APPR impl=v%d | %s | class=%s sel=%r fee=%r sighash=%r'
                      % (VAULT_IMPL_VERSION, msg, rec['class'],
                         rec['selector'], rec['fee'], rec['sighashes']))
        except Exception as e:
            # no record => sign_it will refuse vault inputs (fail-closed)
            vault_log('APPR %s (approval record failed: %s)' % (msg, e))
        return True, msg

# EOF
