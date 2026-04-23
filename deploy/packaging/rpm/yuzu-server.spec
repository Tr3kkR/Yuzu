Name:           yuzu-server
Version:        0.1.0
Release:        1%{?dist}
Summary:        Yuzu endpoint management server
License:        AGPL-3.0-or-later
URL:            https://github.com/Tr3kkR/Yuzu

%description
Enterprise endpoint management platform — server component.
Provides the web dashboard, REST API, gRPC agent service,
instruction engine, policy engine, and all server-side stores.

%install
install -D -m 0755 %{_sourcedir}/yuzu-server %{buildroot}%{_bindir}/yuzu-server
install -D -m 0644 %{_sourcedir}/yuzu-server.service %{buildroot}%{_unitdir}/yuzu-server.service
install -d -m 0750 %{buildroot}/var/lib/yuzu
install -d -m 0750 %{buildroot}/var/log/yuzu
install -d -m 0750 %{buildroot}/etc/yuzu

%pre
getent group yuzu >/dev/null 2>&1 || groupadd -r yuzu
getent passwd yuzu >/dev/null 2>&1 || useradd -r -g yuzu -d /var/lib/yuzu -s /sbin/nologin yuzu

%post
%systemd_post yuzu-server.service

%preun
%systemd_preun yuzu-server.service

%postun
%systemd_postun_with_restart yuzu-server.service

%files
%{_bindir}/yuzu-server
%{_unitdir}/yuzu-server.service
%dir %attr(0750,yuzu,yuzu) /var/lib/yuzu
%dir %attr(0750,yuzu,yuzu) /var/log/yuzu
%dir %attr(0750,yuzu,yuzu) /etc/yuzu
