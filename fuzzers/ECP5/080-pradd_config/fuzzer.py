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

jobs = [
    ("PRADD9_R{}C{}".format(r, c0),     "PRADD9_0",  "PRADD9",  "PRADD9A",  FuzzConfig(job="PRADD9_0",  family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD9_R{}C{}".format(r, c0 + 1), "PRADD9_1",  "PRADD9",  "PRADD9A",  FuzzConfig(job="PRADD9_1",  family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0),     "PRADD18_0", "PRADD18", "PRADD18A", FuzzConfig(job="PRADD18_0", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 1), "PRADD18_1", "PRADD18", "PRADD18A", FuzzConfig(job="PRADD18_1", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD9_R{}C{}".format(r, c0 + 4),  "PRADD9_4",  "PRADD9",  "PRADD9A",  FuzzConfig(job="PRADD9_4",  family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD9_R{}C{}".format(r, c0 + 5),  "PRADD9_5",  "PRADD9",  "PRADD9A",  FuzzConfig(job="PRADD9_5",  family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 4), "PRADD18_4", "PRADD18", "PRADD18A", FuzzConfig(job="PRADD18_4", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    ("PRADD18_R{}C{}".format(r, c0 + 5), "PRADD18_5", "PRADD18", "PRADD18A", FuzzConfig(job="PRADD18_5", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]


def main():
    pytrellis.load_database("../../../database")

    def per_job(job):
        loc, pradd, cmodel, default_mode, cfg = job

        def get_substs(settings, mode=None):
            if mode is None:
                mode = default_mode
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode, cmodel=cmodel,
                        settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "dspconfig.ncl"

        nonrouting.fuzz_enum_setting(cfg, "{}.MODE".format(pradd), ["NONE", default_mode],
                                     lambda x: get_substs(settings={}, mode=x), empty_bitfile, False)

        regs = ["INPUTA", "INPUTB", "INPUTC", "OPPRE"]
        clks = ["NONE", "CLK0", "CLK1", "CLK2", "CLK3"]
        cens = ["CE0", "CE1", "CE2", "CE3"]
        rsts = ["RST0", "RST1", "RST2", "RST3"]
        for reg in regs:
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CLK".format(pradd, reg), clks,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): x}),
                                         empty_bitfile, False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CE".format(pradd, reg), cens,
                                         lambda x: get_substs(settings={"REG_{}_CE".format(reg): x}),
                                         empty_bitfile, False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_RST".format(pradd, reg), rsts,
                                         lambda x: get_substs(settings={"REG_{}_RST".format(reg): x}),
                                         empty_bitfile, False)

        for clk in ["CLK0", "CLK1", "CLK2", "CLK3"]:
            nonrouting.fuzz_enum_setting(cfg, "{}.{}_DIV".format(pradd, clk), ["ENABLED", "DISABLED"],
                                         lambda x: get_substs(settings={"{}_DIV".format(clk): x}), empty_bitfile, False)

        nonrouting.fuzz_enum_setting(cfg, "{}.GSR".format(pradd), ["DISABLED", "ENABLED"],
                                     lambda x: get_substs(settings={"GSR": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.RESETMODE".format(pradd), ["SYNC", "ASYNC"],
                                     lambda x: get_substs(settings={"RESETMODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.CAS_MATCH_REG".format(pradd), ["FALSE", "TRUE"],
                                     lambda x: get_substs(settings={"CAS_MATCH_REG": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.SOURCEA_MODE".format(pradd),
                                     ["A_SHIFT", "C_SHIFT", "A_C_DYNAMIC", "HIGHSPEED"],
                                     lambda x: get_substs(settings={"SOURCEA_MODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.SOURCEB_MODE".format(pradd), ["SHIFT", "PARALLEL", "INTERNAL"],
                                     lambda x: get_substs(settings={"SOURCEB_MODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.FB_MUX".format(pradd),
                                     ["SHIFT", "SHIFT_BYPASS", "DISABLED"],
                                     lambda x: get_substs(settings={"FB_MUX": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.SYMMETRY_MODE".format(pradd), ["DIRECT", "INTERNAL"],
                                     lambda x: get_substs(settings={"SYMMETRY_MODE": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.HIGHSPEED_CLK".format(pradd), clks,
                                     lambda x: get_substs(settings={"HIGHSPEED_CLK": x}), empty_bitfile, False)

    fuzzloops.parallel_foreach(jobs, per_job)


if __name__ == "__main__":
    main()
