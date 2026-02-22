"""Fuzzer 082: Extended CE/RST register mux entries for complete DSP coverage.

Extends fuzzer 081 to cover remaining gaps identified by fill analysis:
  MULT18:  REG_INPUTC_{CE,RST}, REG_OUTPUT_CE (re-fuzz with enhanced NCL)
  PRADD18: REG_INPUTC_{CE,RST} (never fuzzed before)
  ALU54:   REG_INPUTC0_{CE,RST}, REG_INPUTC1_{CE,RST},
           REG_OUTPUT0_CE, REG_OUTPUT1_CE,
           REG_FLAG_{CE,RST} (re-verify from 081)

The key insight: some CE/RST entries may share physical bits with paired
primitives (PRADD INPUTC = MULT INPUTC since they're the same register).
This fuzzer tests both sides to confirm.

Enhancement over 081: ALL register CLKs set to CLK0 in baseline, so every
register is active and CE/RST mux hardware is fully engaged.
"""

from fuzzconfig import FuzzConfig
import nonrouting
import pytrellis
import fuzzloops
import os

DEVICE = os.environ.get("TRELLIS_DEVICE", "LFE5U-25F")

# DSP block coordinates per device
_dsp_rc = {
    "LFE5U-25F": (13, 4),
    "LFE5U-85F": (34, 58),
    "LFE5UM5G-85F": (34, 58),
}

r, c0 = _dsp_rc[DEVICE]

dsp_tiles = ["MIB_R{}C{}:MIB_DSP{}".format(r, c0 + i, i) for i in range(9)] + \
            ["MIB_R{}C{}:MIB2_DSP{}".format(r, c0 + i, i) for i in range(9)]

mult18_jobs = [
    ("MULT18_R{}C{}".format(r, c0),     "MULT18_0", FuzzConfig(job="M18EXT_0", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 1), "MULT18_1", FuzzConfig(job="M18EXT_1", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 4), "MULT18_4", FuzzConfig(job="M18EXT_4", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 5), "MULT18_5", FuzzConfig(job="M18EXT_5", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]

pradd18_jobs = [
    ("PRADD18_R{}C{}".format(r, c0),     "PRADD18_0", FuzzConfig(job="P18EXT_0", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 1), "PRADD18_1", FuzzConfig(job="P18EXT_1", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 4), "PRADD18_4", FuzzConfig(job="P18EXT_4", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 5), "PRADD18_5", FuzzConfig(job="P18EXT_5", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]

alu54_jobs = [
    ("ALU54_R{}C{}".format(r, c0 + 3), "ALU54_3", FuzzConfig(job="A54EXT_3", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("ALU54_R{}C{}".format(r, c0 + 7), "ALU54_7", FuzzConfig(job="A54EXT_7", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]


def main():
    pytrellis.load_database("../../../database")

    cens = ["CE0", "CE1", "CE2", "CE3"]
    rsts = ["RST0", "RST1", "RST2", "RST3"]

    # --- MULT18: INPUTC CE/RST and OUTPUT CE with full register baseline ---
    def per_mult18_job(job):
        def get_substs(settings, mode="MULT18X18D"):
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode,
                        settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        loc, mult, cfg = job
        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "mult18config.ncl"

        base = {
            "REG_INPUTA_CLK": "CLK0", "REG_INPUTB_CLK": "CLK0", "REG_INPUTC_CLK": "CLK0",
            "REG_PIPELINE_CLK": "CLK0", "REG_OUTPUT_CLK": "CLK0",
        }

        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC_CE".format(mult), cens,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC_RST".format(mult), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC_RST=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_OUTPUT_CE".format(mult), cens,
                                     lambda x: get_substs(settings=dict(base, REG_OUTPUT_CE=x)),
                                     empty_bitfile, False)

    fuzzloops.parallel_foreach(mult18_jobs, per_mult18_job)

    # --- PRADD18: INPUTC CE/RST with full register baseline ---
    def per_pradd18_job(job):
        def get_substs(settings, mode="PRADD18A"):
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode,
                        settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        loc, pradd, cfg = job
        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "pradd18config.ncl"

        base = {
            "REG_INPUTA_CLK": "CLK0", "REG_INPUTB_CLK": "CLK0",
            "REG_INPUTC_CLK": "CLK0", "REG_OPPRE_CLK": "CLK0",
        }

        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC_CE".format(pradd), cens,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC_RST".format(pradd), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC_RST=x)),
                                     empty_bitfile, False)

    fuzzloops.parallel_foreach(pradd18_jobs, per_pradd18_job)

    # --- ALU54: INPUTC0/1 CE/RST, OUTPUT0/1 CE, FLAG CE/RST, INPUTCFB CE/RST ---
    def per_alu54_job(job):
        def get_substs(settings, mode="ALU54B"):
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode,
                        settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        loc, alu, cfg = job
        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "alu54config.ncl"

        base = {
            "REG_INPUTC0_CLK": "CLK0", "REG_INPUTC1_CLK": "CLK0",
            "REG_OPCODEOP0_0_CLK": "CLK0", "REG_OPCODEOP0_1_CLK": "CLK0",
            "REG_OPCODEOP1_0_CLK": "CLK0", "REG_OPCODEOP1_1_CLK": "CLK0",
            "REG_OPCODEIN_0_CLK": "CLK0", "REG_OPCODEIN_1_CLK": "CLK0",
            "REG_OUTPUT0_CLK": "CLK0", "REG_OUTPUT1_CLK": "CLK0",
            "REG_FLAG_CLK": "CLK0", "REG_INPUTCFB_CLK": "CLK0",
        }

        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC0_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC0_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC0_RST".format(alu), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC0_RST=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC1_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC1_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTC1_RST".format(alu), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTC1_RST=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_OUTPUT0_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_OUTPUT0_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_OUTPUT1_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_OUTPUT1_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_FLAG_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_FLAG_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_FLAG_RST".format(alu), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_FLAG_RST=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTCFB_CE".format(alu), cens,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTCFB_CE=x)),
                                     empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTCFB_RST".format(alu), rsts,
                                     lambda x: get_substs(settings=dict(base, REG_INPUTCFB_RST=x)),
                                     empty_bitfile, False)

    fuzzloops.parallel_foreach(alu54_jobs, per_alu54_job)


if __name__ == "__main__":
    main()
