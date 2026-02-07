import os
from fuzzconfig import FuzzConfig
import nonrouting
import pytrellis
import fuzzloops

DEVICE = os.environ.get("TRELLIS_DEVICE", "LFE5U-25F")


def dsp_tiles_for(device):
    # Pick a single representative DSP block and include its MIB/MIB2 tiles.
    #
    # - LFE5U-25F: historical coordinate used by upstream fuzzers
    # - LFE5UM5G-85F: choose a middle-ish DSP group on row 34 (see tilegrid.json)
    if device == "LFE5U-25F":
        r, c0 = 13, 4
    elif device in ("LFE5U-85F", "LFE5UM5G-85F"):
        r, c0 = 34, 58
    else:
        raise RuntimeError("Unsupported TRELLIS_DEVICE '{}' for this fuzzer".format(device))

    tiles = []
    for i in range(9):
        c = c0 + i
        tiles.append("MIB_R{}C{}:MIB_DSP{}".format(r, c, i))
        tiles.append("MIB_R{}C{}:MIB2_DSP{}".format(r, c, i))
    return tiles


dsp_tiles = dsp_tiles_for(DEVICE)

if DEVICE == "LFE5U-25F":
    loc0, loc1 = "MULT9_R13C4", "MULT9_R13C5"
elif DEVICE in ("LFE5U-85F", "LFE5UM5G-85F"):
    loc0, loc1 = "MULT9_R34C58", "MULT9_R34C59"
else:
    raise RuntimeError("Unsupported TRELLIS_DEVICE '{}' for this fuzzer".format(DEVICE))

jobs = [
    (loc0, "MULT9_0", FuzzConfig(job="MULT9_0", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    (loc1, "MULT9_1", FuzzConfig(job="MULT9_1", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]


def main():
    pytrellis.load_database("../../../database")

    def per_job(job):
        def get_substs(settings, mode="MULT9X9D"):
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode, settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        loc, mult, cfg = job
        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "dspconfig.ncl"

        nonrouting.fuzz_enum_setting(cfg, "{}.MODE".format(mult), ["NONE", "MULT9X9D"],
                                     lambda x: get_substs(settings={}, mode=x), empty_bitfile, False)

        regs = ["INPUTA", "INPUTB", "INPUTC", "PIPELINE", "OUTPUT"]
        clks = ["NONE", "CLK0", "CLK1", "CLK2", "CLK3"]
        cens = ["CE0", "CE1", "CE2", "CE3"]
        rsts = ["RST0", "RST1", "RST2", "RST3"]
        for reg in regs:
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CLK".format(mult, reg), clks,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): x}), empty_bitfile,
                                         False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CE".format(mult, reg), cens,
                                         lambda x: get_substs(settings={"REG_{}_CE".format(reg): x}), empty_bitfile,
                                         False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_RST".format(mult, reg), rsts,
                                         lambda x: get_substs(settings={"REG_{}_RST".format(reg): x}), empty_bitfile,
                                         False)

        for clk in ["CLK0", "CLK1", "CLK2", "CLK3"]:
            nonrouting.fuzz_enum_setting(cfg, "{}.{}_DIV".format(mult, clk), ["ENABLED", "DISABLED"],
                                         lambda x: get_substs(settings={"{}_DIV".format(clk): x}), empty_bitfile, False)

        nonrouting.fuzz_enum_setting(cfg, "{}.CAS_MATCH_REG".format(mult), ["FALSE", "TRUE"],
                                     lambda x: get_substs(settings={"CAS_MATCH_REG": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.MULT_BYPASS".format(mult), ["DISABLED", "ENABLED"],
                                     lambda x: get_substs(settings={"MULT_BYPASS": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.GSR".format(mult), ["DISABLED", "ENABLED"],
                                     lambda x: get_substs(settings={"GSR": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.RESETMODE".format(mult), ["SYNC", "ASYNC"],
                                     lambda x: get_substs(settings={"RESETMODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.SOURCEB_MODE".format(mult),
                                     ["B_SHIFT", "C_SHIFT", "B_C_DYNAMIC", "HIGHSPEED"],
                                     lambda x: get_substs(settings={"SOURCEB_MODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.HIGHSPEED_CLK".format(mult), clks,
                                     lambda x: get_substs(settings={"HIGHSPEED_CLK": x}), empty_bitfile, False)

    fuzzloops.parallel_foreach(jobs, per_job)


if __name__ == "__main__":
    main()
