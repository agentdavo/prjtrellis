"""Fuzzer 081: MULT18 and ALU54 CE/RST register mux entries.

The upstream 073-mult18_config and 075-alu54b_config fuzzers test CE/RST
with CLK=NONE (default), so the register hardware isn't instantiated and
CE/RST mux bits produce no bitstream delta.  This fuzzer sets CLK=CLK0
as baseline when testing CE/RST, which enables the register so CE/RST
selector bits become visible.

Covers:
  MULT18:  REG_INPUTC_{CE,RST}, REG_OUTPUT_{CE,RST}
  ALU54:   REG_INPUTC0_{CE,RST}, REG_INPUTC1_{CE,RST},
           REG_OUTPUT0_{CE,RST}, REG_OUTPUT1_{CE,RST},
           REG_FLAG_{CE,RST}, REG_INPUTCFB_{CLK,CE,RST}
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
    ("MULT18_R{}C{}".format(r, c0),     "MULT18_0", FuzzConfig(job="M18CE_0", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 1), "MULT18_1", FuzzConfig(job="M18CE_1", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 4), "MULT18_4", FuzzConfig(job="M18CE_4", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("MULT18_R{}C{}".format(r, c0 + 5), "MULT18_5", FuzzConfig(job="M18CE_5", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]

alu54_jobs = [
    ("ALU54_R{}C{}".format(r, c0 + 3), "ALU54_3", FuzzConfig(job="A54CE_3", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("ALU54_R{}C{}".format(r, c0 + 7), "ALU54_7", FuzzConfig(job="A54CE_7", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]


def main():
    pytrellis.load_database("../../../database")

    cens = ["CE0", "CE1", "CE2", "CE3"]
    rsts = ["RST0", "RST1", "RST2", "RST3"]
    clks = ["NONE", "CLK0", "CLK1", "CLK2", "CLK3"]

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

        for reg in ["INPUTC", "OUTPUT"]:
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CE".format(mult, reg), cens,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): "CLK0",
                                                                        "REG_{}_CE".format(reg): x}),
                                         empty_bitfile, False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_RST".format(mult, reg), rsts,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): "CLK0",
                                                                        "REG_{}_RST".format(reg): x}),
                                         empty_bitfile, False)

    fuzzloops.parallel_foreach(mult18_jobs, per_mult18_job)

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

        for reg in ["INPUTC0", "INPUTC1", "OUTPUT0", "OUTPUT1", "FLAG", "INPUTCFB"]:
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CE".format(alu, reg), cens,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): "CLK0",
                                                                        "REG_{}_CE".format(reg): x}),
                                         empty_bitfile, False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_RST".format(alu, reg), rsts,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): "CLK0",
                                                                        "REG_{}_RST".format(reg): x}),
                                         empty_bitfile, False)

        # INPUTCFB CLK entirely missing from upstream 075
        nonrouting.fuzz_enum_setting(cfg, "{}.REG_INPUTCFB_CLK".format(alu), clks,
                                     lambda x: get_substs(settings={"REG_INPUTCFB_CLK": x}),
                                     empty_bitfile, False)

    fuzzloops.parallel_foreach(alu54_jobs, per_alu54_job)


if __name__ == "__main__":
    main()
