# All changes to build and install RPM packages go here.
#
# The upatch.spec file may only be applicable to the rpm package building
# method, and can adapt to RHEL/Fedora/openEuler/CentOS/AlmaLinux/RockyLinux
# and other RHEL-like Linux distribution operating systems. If you want to
# support Debian (usually means deb package), obviously you cannot use this
# ulpatch.spec.

# Default disable ulftrace, beacuse it's is unimplemented.
%define with_ulftrace	0

# Default enable ultask
%define with_ultask	1

# By default, the capstone disassembly function is supported, which is helpful
# for debugging.
%define with_capstone	0%{?!_without_capstone:1}
%define with_libunwind	0%{?!_without_libunwind:1}

# Compile executions as PIE or not
%define build_pie	0%{?pie}

Name:		ulpatch
# The version number must be consistent with the CMakeLists.txt in the
# top-level directory.
Version:	0.5.12
Release:	3%{?dist}
Summary:	Userspace Live Patch Toolset

License:	GPL-2.0 or later
URL:		https://github.com/Rtoax/ulpatch

Source0:	ulpatch-v%{version}.tar.gz

Recommends:	bash-completion

# ========== build requires ==========

BuildRequires:	binutils-devel
%if "%{toolchain}" == "clang"
BuildRequires:  clang
%else
BuildRequires:  gcc
%endif
BuildRequires:  cmake
BuildRequires:	elfutils-devel
BuildRequires:	elfutils-libelf-devel
BuildRequires:	glibc-devel
%if 0%{?with_libunwind}
BuildRequires:  libunwind-devel
%endif
%if 0%{?with_capstone}
BuildRequires:  capstone-devel
%endif

%if 0%{?fedora} > 40 || 0%{?rhel} > 10
BuildRequires:	bash-completion-devel
%else
BuildRequires:	bash-completion
%endif

Requires:	binutils
%if 0%{?with_libunwind}
Requires:	libunwind
%endif
%if 0%{?with_capstone}
Requires:	capstone
%endif
Requires:	elfutils-libelf

Provides:	%{name} = %{version}-%{release}
Provides:	%{name}-command(ulpatch)
Provides:	%{name}-command(ulpinfo)
Provides:	%{name}-command(ulptask)
Provides:	%{name}-command(ulpconfig)
%if 0%{?with_ulftrace}
Provides:	%{name}-command(ulftrace)
%endif
Provides:	%{name}-man = %{version}-%{release}
Provides:	%{name}-bash-completion = %{version}-%{release}

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
%ifnarch aarch64 x86_64
echo "ERROR: Not support architecture but aarch64, x86_64"
exit 1
%endif

%setup -q -n ulpatch-v%{version}

%build
pushd %{_builddir}/ulpatch-v%{version}
mkdir build
pushd build
cmake -DCMAKE_BUILD_TYPE=Release \
%if "%{toolchain}" == "clang"
	-DCMAKE_C_COMPILER=clang \
%endif
%if %{build_pie}
	-DCONFIG_BUILD_PIE_EXE=ON \
%endif
%if !%{?with_ulftrace}
	-DCONFIG_BUILD_ULFTRACE=OFF \
%endif
%if !%{?with_libunwind}
	-DCONFIG_LIBUNWIND=OFF \
%endif
%if !%{?with_capstone}
	-DCONFIG_CAPSTONE=OFF \
%endif
	..
make %{?_smp_mflags}
popd
popd

%install
pushd %{_builddir}/ulpatch-v%{version}/build/
make install DESTDIR="%{buildroot}"
popd

%check
%{buildroot}/%{_bindir}/ulpatch_test --version
%{buildroot}/%{_bindir}/ulpatch_test --info
# FIXME: remove '|| true'
%{buildroot}/%{_bindir}/ulpatch_test || true

%files
%{_bindir}/ulpatch
%if 0%{?with_ulftrace}
%{_bindir}/ulftrace
%endif
%{_bindir}/ulpinfo
%if 0%{?with_ultask}
%{_bindir}/ultask
%endif
%if 0%{?with_ulftrace}
%{_mandir}/man8/ulftrace.8.gz
%endif
%{_mandir}/man8/ulpatch.8.gz
%{_mandir}/man8/ulpinfo.8.gz
%if 0%{?with_ultask}
%{_mandir}/man8/ultask.8.gz
%endif
%{_datadir}/ulpatch/ftrace/ftrace-mcount.obj
%dir %{_datadir}/bash-completion/
%dir %{_datadir}/bash-completion/completions/
%{_datadir}/bash-completion/completions/ulpatch
%{_datadir}/bash-completion/completions/ulpinfo
%{_datadir}/bash-completion/completions/ulpconfig
%if 0%{?with_ultask}
%{_datadir}/bash-completion/completions/ultask
%endif
%if 0%{?with_ulftrace}
%{_datadir}/bash-completion/completions/ulftrace
%endif
%license LICENSE

%files devel
%{_includedir}/ulpatch/asm.h
%{_includedir}/ulpatch/meta.h
%{_bindir}/ulpconfig
%{_mandir}/man8/ulpconfig.8.gz

%files tests
%{_bindir}/ulpatch_test
%{_datadir}/ulpatch/ulpatches/empty.ulp
%{_datadir}/ulpatch/ulpatches/printf.ulp

%changelog
* Thu Jan 02 2025 Rong Tao <rtoax@foxmail.com> - 0.5.12-3
- Not release yet.

