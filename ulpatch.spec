# All changes to build and install RPM packages go here.
#
# The upatch.spec file may only be applicable to the rpm package building
# method, and can adapt to RHEL/Fedora/openEuler/CentOS/AlmaLinux/RockyLinux
# and other RHEL-like Linux distribution operating systems. If you want to
# support Debian (usually means deb package), obviously you cannot use this
# ulpatch.spec.

# Default disable ulftrace, beacuse it's is unimplemented.
%define with_ulftrace	0
# By default, the capstone disassembly function is supported, which is helpful
# for debugging.
%define with_capstone	0%{?!_without_capstone:1}

Name:		ulpatch
# The version number must be consistent with the CMakeLists.txt in the
# top-level directory.
Version:	0.5.11
Release:	0%{?dist}
Summary:	Userspace Live Patch

License:	GPL-2.0
URL:		https://github.com/Rtoax/ulpatch

Source0:	ulpatch-v%{version}.tar.gz

BuildRequires:	binutils-devel
BuildRequires:  cmake
BuildRequires:	elfutils-devel
BuildRequires:	elfutils-libelf-devel
BuildRequires:	glibc-devel
BuildRequires:  libunwind-devel
%if 0%{?with_capstone}
BuildRequires:  capstone-devel
%endif

Requires:	libunwind
Requires:	elfutils-libelf

Provides:	%{name} = %{version}-%{release}

%package devel
Summary:	The ULPatch's development headers.
BuildArch:	noarch
License:	LGPLv2+ and MIT
Requires:	%{name} = %{version}-%{release}
Provides:	%{name}-devel = %{version}-%{release}

%package tests
Summary:	The ULPatch's tests.
License:	LGPLv2+ and MIT
Requires:	%{name} = %{version}-%{release}
Requires:	%{name}-devel = %{version}-%{release}
Provides:	%{name}-tests = %{version}-%{release}

%description
ULPatch is open source user space live patch tool.

%description devel
Development headers and auxiliary files for developing ULPatch patch.

%description tests
ULPatch tests.

%prep
echo "Prep"
%ifnarch aarch64 x86_64
echo "Not support architecture but aarch64, x86_64"
exit 1
%endif

%setup -q -n ulpatch-v%{version}

%build
echo "Build"
pushd %{_builddir}/ulpatch-v%{version}
mkdir build
pushd build
cmake -DCMAKE_BUILD_TYPE=Release \
%if !%{?with_ulftrace}
	-DCONFIG_BUILD_ULFTRACE=OFF \
%endif
%if !%{?with_capstone}
	-DCONFIG_CAPSTONE=OFF \
%endif
	..
make %{?_smp_mflags}
popd
popd

%install
echo "Install"
pushd %{_builddir}/ulpatch-v%{version}/build/
make install DESTDIR="%{buildroot}"
popd

%check
echo "Check"
%{_bindir}/ulpatch_test --version
%{_bindir}/ulpatch_test

%files
%{_bindir}/ulpatch
%if 0%{?with_ulftrace}
%{_bindir}/ulftrace
%endif
%{_bindir}/ulpinfo
%{_bindir}/ultask
%if 0%{?with_ulftrace}
%{_mandir}/man8/ulftrace.8.gz
%endif
%{_mandir}/man8/ulpatch.8.gz
%{_mandir}/man8/ulpinfo.8.gz
%{_mandir}/man8/ultask.8.gz
%{_datadir}/ulpatch/ftrace/ftrace-mcount.obj
%license LICENSE

%files devel
%{_includedir}/ulpatch/asm.h
%{_includedir}/ulpatch/meta.h
%{_bindir}/ulp-config
%{_mandir}/man8/ulp-config.8.gz

%files tests
%{_bindir}/ulpatch_test
%{_datadir}/ulpatch/ulpatches/empty.ulp
%{_datadir}/ulpatch/ulpatches/printf.ulp

%changelog
* Sat Dec 14 2024 Rong Tao <rtoax@foxmail.com> - 0.5.11-0
- Not release yet.

