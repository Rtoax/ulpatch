# All changes to build and install RPM packages go here.
Name:		ulpatch
Version:	0.5.3
Release:	1%{?dist}
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

Requires:	libunwind
Requires:	elfutils-libelf

Provides:	%{name} = %{version}-%{release}

%package devel
Summary:	The ULPatch's development headers.
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
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j4
popd
popd

%install
echo "Install"
pushd %{_builddir}/ulpatch-v%{version}/build/
make install DESTDIR="%{buildroot}"
popd

%check

%files
%{_bindir}/ulpatch
%{_bindir}/ulftrace
%{_bindir}/ulpinfo
%{_bindir}/ultask
%{_mandir}/man8/ulftrace.8.gz
%{_mandir}/man8/ulpatch.8.gz
%{_mandir}/man8/ulpinfo.8.gz
%{_mandir}/man8/ultask.8.gz
%{_datadir}/ulpatch/ftrace-mcount.obj
%{_datadir}/ulpatch/ulpatch-hello.obj

%files devel
%{_includedir}/ulpatch/meta.h

%files tests
%{_bindir}/ulpatch_test

%changelog
* Tue Apr 02 2024 Rong Tao <rtoax@foxmail.com> - 0.5.3-1
- Create this.

