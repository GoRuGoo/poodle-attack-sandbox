#!/bin/bash

# URLを指定
URL="https://testdomain.com"

# 255回ループして実行
for i in {1..255}; do
  echo "Executing request #$i"
  curl -X POST $URL --insecure
done

echo "All requests completed."

