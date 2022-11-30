@echo off
:selfkill
if exist %1 del %1
if exist %1 goto selfkill
del %0