# Copyright 2026 Free Mobile, Vincent Jardin

%global commit      5c05dc22778de3b87c819a8a3f31f1816fe87426
%global shortcommit %(echo %{commit} | cut -c1-7)
%global snapdate    20260905

Name:           cst
Version:        2.0^%{snapdate}git%{shortcommit}
Release:        1%{?dist}
Summary:        NXP Code Signing Tool for QorIQ and Layerscape secure boot

License:        BSD-3-Clause
URL:            https://github.com/nxp-qoriq/cst
Source0:        https://github.com/vjardin/cst/archive/%{commit}/%{name}-%{shortcommit}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
# tests/smoke.sh verifies the signatures with the openssl command
BuildRequires:  openssl
Recommends:     openssl

%description
CST generates the RSA key pairs, CSF headers and signatures used by the
secure boot flow of NXP QorIQ and Layerscape processors: ISBC and ESBC
headers, PBI/RCW signing, CF headers for non-PBL devices, OTPMK and debug
response values, and fuse provisioning scripts.

The sample input files and the per-platform signing scripts are installed
under %{_datadir}/%{name}.

%prep
%autosetup -n %{name}-%{commit}

%build
%make_build

%install
install -D -m 755 -t %{buildroot}%{_bindir} \
        create_hdr_isbc create_hdr_esbc create_hdr_pbi create_hdr_cf \
        gen_keys gen_otpmk_drbg gen_drv_drbg gen_sign sign_embed gen_fusescr \
        scripts/uni_sign scripts/uni_pbi scripts/uni_cfsign
install -d %{buildroot}%{_datadir}/%{name}
cp -r input_files scripts/platforms %{buildroot}%{_datadir}/%{name}/
# stray shell snippet committed upstream by mistake
rm -f %{buildroot}%{_datadir}/%{name}/input_files/wer
install -m 644 byte_swap.tcl %{buildroot}%{_datadir}/%{name}/

%check
tests/smoke.sh

%files
%license LICENSE
%doc README
%{_bindir}/create_hdr_isbc
%{_bindir}/create_hdr_esbc
%{_bindir}/create_hdr_pbi
%{_bindir}/create_hdr_cf
%{_bindir}/gen_keys
%{_bindir}/gen_otpmk_drbg
%{_bindir}/gen_drv_drbg
%{_bindir}/gen_sign
%{_bindir}/sign_embed
%{_bindir}/gen_fusescr
%{_bindir}/uni_sign
%{_bindir}/uni_pbi
%{_bindir}/uni_cfsign
%{_datadir}/%{name}/

%changelog
* Sat Sep 05 2026 Vincent Jardin <vjardin@free.fr> - 2.0^20260905git5c05dc2-1
- Initial package, snapshot of commit 5c05dc2
