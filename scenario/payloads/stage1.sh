#!/bin/sh
# Harmless second stage for the lab: prints text and lists /tmp.
echo "stage1 ran"
ls /tmp > /dev/null
