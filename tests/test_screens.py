from sambatui.screens import infer_domain_from_server


def test_infer_domain_from_server_fqdn() -> None:
    assert infer_domain_from_server("dc01.example.com") == "example.com"


def test_infer_domain_from_server_ignores_ip_and_short_hostname() -> None:
    assert infer_domain_from_server("192.0.2.10") == ""
    assert infer_domain_from_server("dc01") == ""


def test_infer_domain_from_server_strips_url_and_port() -> None:
    assert infer_domain_from_server("ldap://dc01.example.com:389") == "example.com"
