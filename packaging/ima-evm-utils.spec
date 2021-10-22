Name:		ima-evm-utils
Version:	1.4
Release:	1%{?dist}
Summary:	ima-evm-utils - IMA/EVM control utility
Group:		System/Libraries
License:	GPLv2
#URL:		
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:    autoconf
BuildRequires:    automake
BuildRequires:    openssl-devel
BuildRequires:    keyutils-libs-devel

%description
This package provide IMA/EVM control utility

%prep
%setup -q

%build
./autogen.sh
%configure --prefix=/usr
make

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
exit 0

%preun -p /sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/libimaevm.*
%{_includedir}/*

%changelog
* Thu Apr 05 2012 Dmitry Kasatkin <dmitry.kasatkin@intel.com>
- Initial RPM spec file

