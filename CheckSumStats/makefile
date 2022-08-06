#nmake makefile
EXECUTABLE_NAME = CheckSumStats.exe

CheckSumStats.obj : CheckSumStats.cpp
 @echo.
 @echo Compiling...
 cl /GS /GL /W3 /Gy /Zc:wchar_t /Gm- /O2 /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /WX- /Zc:forScope /Gd /Oi /MT /EHsc /nologo CheckSumStats.cpp
 @echo Compiling done! 

$(EXECUTABLE_NAME) : CheckSumStats.obj
 @echo.
 @echo Linking...
 link /out:$(EXECUTABLE_NAME) /NXCOMPAT /DYNAMICBASE /MACHINE:X64 /OPT:REF /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /OPT:ICF /NOLOGO CheckSumStats.obj
 @echo Linking done!

cleanup:
 @echo.
 @echo Cleanup...
 del CheckSumStats.obj
 del $(EXECUTABLE_NAME)
 @echo Cleanup done!

all: cleanup $(EXECUTABLE_NAME)