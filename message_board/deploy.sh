#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <server_address> <www_directory> <cgi_bin_directory>"
  exit 1
fi

# Variables from arguments
SERVER="$1"
WWW_DIR="$2"
CGI_BIN_DIR="$3"
CLIENT_LOCAL_DIR="client"
CGI_BIN_LOCAL_DIR="cgi/bin"

# Step 1: Deploy client files to the server
[ -d $CLIENT_LOCAL_DIR/dist ] || { echo "Client 'dist' directory not found!"; exit 1; }
echo "Deploying client files to the server..."
scp -r $CLIENT_LOCAL_DIR/dist/* $SERVER:$WWW_DIR || { echo "Failed to copy client files!"; exit 1; }

# Step 2: Deploy CGI scripts to the server
echo "Deploying CGI scripts to the server..."
scp -r $CGI_BIN_LOCAL_DIR/* $SERVER:$CGI_BIN_DIR || { echo "Failed to copy CGI scripts!"; exit 1; }

# Step 4: Set executable permissions for CGI scripts
echo "Setting executable permissions for CGI scripts..."
ssh $SERVER "chmod +x $CGI_BIN_DIR/*" || { echo "Failed to set permissions on CGI scripts!"; exit 1; }

echo "Deployment completed successfully!"
