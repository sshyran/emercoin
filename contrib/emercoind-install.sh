#!/bin/sh
# Install script for Emercoin Daemin and 2 cli - mainnet/testnet
# Before install, you needed to create usernames/group:

EMCGROUP=emercoin
EMCUSER=emc
TEMCUSER=temc

DST=${1:-'/usr/local/bin'}

function install_cli() {
  cp emercoin-cli $DST/$1
  chown $1:$EMCGROUP $DST/$1
  chmod 4750 $DST/$1
}

echo "Install emercoin to: $DST"
cp emercoind $DST/emercoind
chown root:$EMCGROUP $DST/emercoind
chmod 750  $DST/emercoind

install_cli $EMCUSER
install_cli $TEMCUSER

