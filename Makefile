#
# Copyright (C) 2010-2015 Jo-Philipp Wich <jow@openwrt.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
	PKG_NAME:=TrafficManagement
	PKG_RELEASE:=1
	PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk

define Package/TrafficManagement
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Demo For Project
	MAINTAINER:= Minkoo HWANG
	DEPENDS:=+libpcap
endef

define Package/TrafficManagement/description
	DEMO VIDEO calculatetraffic is program that calculate number of packet per IP
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/TrafficManagement TrafficManagement.c -lpcap
endef

define Package/TrafficManagement/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/TrafficManagement $(1)/usr/sbin/TrafficManagement
endef
$(eval $(call BuildPackage,TrafficManagement))
