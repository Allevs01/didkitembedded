#!/bin/bash

# Avviare il programma Rust in background
./10claim &

# PID del programma Rust
PID=$!

# Raccolta dati CPU con top
top -b -d 1 -n 10 > cpu_usage.txt &

# Attendere che il programma Rust termini
wait $PID

echo "Raccolta dati completata."