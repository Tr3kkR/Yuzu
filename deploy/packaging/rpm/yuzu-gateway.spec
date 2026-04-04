Name:           yuzu-gateway
Version:        0.1.0
Release:        1%{?dist}
Summary:        Yuzu endpoint management gateway
License:        Apache-2.0
URL:            https://github.com/Tr3kkR/Yuzu

# The Erlang release bundles crypto.so with broad OpenSSL runpaths from upstream.
# This is a self-contained release with embedded ERTS — runpath validation is not applicable.
%define __brp_check_rpaths %{nil}
AutoReqProv:    no

%description
Erlang/OTP gateway node for scaling Yuzu agent connections.
Routes commands from the server to agents and aggregates responses.
Self-contained — includes embedded Erlang runtime.

%install
# Install the entire Erlang release to /opt/yuzu_gw
install -d %{buildroot}/opt/yuzu_gw
cp -a %{_sourcedir}/yuzu_gw/* %{buildroot}/opt/yuzu_gw/

# Systemd service
install -D -m 0644 %{_sourcedir}/yuzu-gateway.service %{buildroot}%{_unitdir}/yuzu-gateway.service

# Log directory
install -d -m 0755 %{buildroot}/var/log/yuzu

%pre
getent group yuzu-gw >/dev/null 2>&1 || groupadd -r yuzu-gw
getent passwd yuzu-gw >/dev/null 2>&1 || useradd -r -g yuzu-gw -d /opt/yuzu_gw -s /sbin/nologin yuzu-gw

%post
%systemd_post yuzu-gateway.service
chown -R yuzu-gw:yuzu-gw /opt/yuzu_gw

%preun
%systemd_preun yuzu-gateway.service

%postun
%systemd_postun_with_restart yuzu-gateway.service

%files
/opt/yuzu_gw
%{_unitdir}/yuzu-gateway.service
%dir %attr(0755,yuzu-gw,yuzu-gw) /var/log/yuzu

%changelog
* Fri Apr 04 2026 Yuzu Team <noreply@yuzu.io> - 0.1.0-1
- Initial RPM packaging
