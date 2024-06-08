#!/usr/bin/env bash

case $1 in
entity)
  export DATABASE_URL='sqlite:./migration/authenticator.db?mode=rwc'
  sea-orm-cli generate entity -o src/app/repo/ent
  ;;
bridge)
  cd flutter || exit
  flutter_rust_bridge_codegen.exe generate
  cd ..
  ;;
esac