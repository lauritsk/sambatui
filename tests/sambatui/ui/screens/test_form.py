from hypothesis import given
from hypothesis import strategies as st

from sambatui.ui.screens import infer_domain_from_server

DNS_LABEL = st.from_regex(r"[a-z](?:[a-z-]{0,18}[a-z])?", fullmatch=True)
DNS_NAME = st.lists(DNS_LABEL, min_size=2, max_size=4).map(".".join)


@given(DNS_LABEL, DNS_NAME)
def test_infer_domain_from_server_fqdn(host: str, domain: str) -> None:
    assert infer_domain_from_server(f"{host}.{domain}") == domain


@given(st.one_of(st.ip_addresses(v=4).map(str), DNS_LABEL))
def test_infer_domain_from_server_ignores_ip_and_short_hostname(server: str) -> None:
    assert infer_domain_from_server(server) == ""


@given(DNS_LABEL, DNS_NAME, st.integers(min_value=1, max_value=65535))
def test_infer_domain_from_server_strips_url_and_port(
    host: str, domain: str, port: int
) -> None:
    assert infer_domain_from_server(f"ldap://{host}.{domain}:{port}") == domain
