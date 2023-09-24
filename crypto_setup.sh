
#!/bin/bash

# crypto package 

PKG_DIR="crypto"

# grant permissions if not existant
if [[ ! -r ${PKG_DIR}  || ! -w ${PKG_DIR} || ! -x ${PKG_DIR} ]]; then
   chmod -R 755 "${PKG_DIR}"
fi

# get into the package directory and set up the external dependencies
(
    cd "${PKG_DIR}" || { echo "cd into the GOPATH package folder failed"; exit 1; }
    go generate
)
