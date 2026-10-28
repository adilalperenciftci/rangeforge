import pytest

from rangeforge.datasets.evtx_attack_samples import techniques_from_name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("4794_DSRM_password_change_t1098", ("T1098",)),
        ("Exec_sysmon_1_lolbin_T1218.011_rundll32", ("T1218.011",)),
        ("CA_DCSync_4662", ("T1003.006",)),
        ("CA_Mimikatz_Memssp_Default_Logs_Sysmon_11", ("T1003.001",)),
        ("LM_PsExec_rename_sysmon_1_3", ("T1569.002",)),
        ("random_sample_with_no_hint", ()),
        ("T1055_T1574_combo", ("T1055", "T1574")),
    ],
)
def test_techniques_from_name(name: str, expected: tuple[str, ...]) -> None:
    assert techniques_from_name(name) == expected
