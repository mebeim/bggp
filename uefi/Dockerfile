#
# @mebeim - 2024-07-09
#

FROM debian:12 AS builder

ARG EDK2_BUILD_TYPE=RELEASE
ARG EDK2_TAG=edk2-stable202405

#
# Build dependencies
#
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git binutils gcc g++ make nasm iasl \
	libc6-dev uuid-dev python3 python-is-python3

#
# Clone, patch and build EDK II
#
RUN mkdir /build
WORKDIR /build

RUN git clone --depth 1 --single-branch --branch ${EDK2_TAG} \
	--recursive --shallow-submodules https://github.com/tianocore/edk2.git
	WORKDIR /build/edk2

# Apply two patches:
# - Patch OvmfPkgX64.dsc to also compile RngDxe (needed for Ip4Dxe and possibly
#   others too, but somehow not included... weird).
# - Patch TlsLib to skip TLS handshake verification. This is just a shortcut to
#   make things easier. Host CA certificates could also be packed into a certdb
#   and passed to UEFI code through QEMU, but that's more tedious.
RUN --mount=type=bind,source=edk2_patches/,target=/patches \
	git apply --ignore-whitespace /patches/ovmf_*.patch

# Build OVMF with HTTP + TLS support
RUN bash -c '\
	cd /build/edk2 && \
	source edksetup.sh && \
	make -j -C BaseTools && \
	build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t GCC5 -b ${EDK2_BUILD_TYPE} -n 0 \
		-D NETWORK_HTTP_ENABLE=TRUE \
		-D NETWORK_ALLOW_HTTP_CONNECTIONS=TRUE \
		-D NETWORK_TLS_ENABLE=TRUE'

#
# Copy build output to standalone container to be easily extracted
#

RUN mkdir -p /output
WORKDIR /build/edk2

# Copy OVMF code, OVMF vars and EFI drivers
RUN bash -c '\
	cd Build/OvmfX64/RELEASE_GCC5 && \
	cp FV/OVMF_{CODE,VARS}.fd /output && \
	cp X64/{Snp,Mnp,Arp,Rng,Ip4,Dhcp4,Udp4,Dns,Tcp,Tls,Http,HttpUtilities}Dxe.efi /output'

# Also add the UEFI shell startup script
COPY startup.nsh /output/

FROM scratch AS release
COPY --from=builder /output /
