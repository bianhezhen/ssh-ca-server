#!/bin/bash

gunicorn -w 4 ssh_ca_server:app
