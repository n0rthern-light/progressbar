# Progressbar

![smooth-loader](https://github.com/user-attachments/assets/1c1c99ab-147d-4f74-a5db-2cbd3a3a163b)

A C++ Win32 progress bar system that uses strategically placed markers in the source code. After compilation, a Python script disassembles the binary, detects marker positions, and assigns progress values, enabling accurate UI progress tracking.

## Prerequisites

1. Architecture x86 - not tested on x64
2. Compiler MSVC C++
3. Python 3+
4. Python modules
	1. `capstone`
	2. `pefile`
## Installation

1. Add `progressbar.hpp` and `progressbar.cpp` to your C++ project.
2. Place `progressbar.py` within your project directory.
3. Enable map file generation for your target binary.
4. Install post build event script.
```sh
py.exe "$(ProjectDir)progressbar.py" "$(TargetDir)$(TargetName).exe" "$(TargetDir)$(TargetName).map" "<start_fn>" "<marker_fn>" "<allowed_fn1>|<allowed_fn2>..."
```

## Script parameters

- `<start_fn>`: A fragment of the mangled symbol name for the root function where the progress bar process is initialized. This serves as the starting point for the script to begin its search.
- `<marker_fn>`: A fragment of the mangled symbol name for the progress bar marker function. If the progress bar code is unmodified, use `?Marker@progressbar@@` as the fragment.
- `<allowed_fn*>`: A list of fragments of mangled symbol names for functions, separated by the pipe (`|`) character, that the script is allowed to search and scan recursively. The patching script begins at `<start_fn>` and searches for progress bar markers. If it encounters a call to any function whose fragment matches the allowed list, it will enter that function and continue scanning. This process is repeated recursively for functions in the allowed list, up to a depth of 3 levels.

## Usage

1. Include `progressbar.hpp`.
2. Register progressbar handler using `progress::SetProgressbarHandler` function.
3. Use `PROGRESSBAR_MARKER` macro between code blocks of your choice.
4. Build binary and make the post-compile script do the work.

## Example code

The following code defines a custom progress bar handler function and assigns it immediately after the function prologue using `progressbar::SetProgressbarHandler` function. Each major task in the program is marked using the `PROGRESSBAR_MARKER` macro.

```c++
#include "progressbar.hpp"

// sample progressbar handler logic, called on each marker at runtime.
void __stdcall ipcProgressbarHandler(progressbar::step_value_t currentStep, progressbar::step_value_t maxStep)
{
    PROTECT_SOFT

    ipc::cl_send_message(
        g_connection,
        messages::TYPE_PROGRESS,
        { (BYTE)((float)currentStep / (float)maxStep * 100.f) }
    );
}

void heavyTask()
{
	heavyTask_innerTask();
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(2, 6) call
	heavyTask_anotherInnerTask();
}

void anotherHeavyTask()
{
	heavyTask_innerTask();
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(4, 6) call
	heavyTask_anotherInnerTask();
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(5, 6) call
	heavyTask_anotherAnotherInnerTask();
}

int main()
{
	// register handler function
	progressbar::SetProgressbarHandler(ipcProgressbarHandler);

	// do some heavy-lifting and mark progress
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(1, 6) call
	heavyTask();
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(3, 6) call
	anotherHeavyTask();
	PROGRESSBAR_MARKER // leads to ipcProgressbarHandler(6, 6) call

	return 0;
}
```

## How it works

Once compiled, the binary includes code that requires post-processing and patching to activate the progress bar mechanism:

![ida-before](https://github.com/user-attachments/assets/4b7cccb2-620e-4a76-89b8-13ee74facbe2)

As you can see, the `progressbar::Marker` function is invoked with placeholder parameters `0xDEADBEEF` and `0xBABEFACE`.

After patching with `progressbar.py`. The decompiled binary code looks as follows:

![ida-after](https://github.com/user-attachments/assets/8b6dd7da-fc89-4fa2-8a4d-8063d0109000)

The respective values of `currentStep` and `maxStep` are assigned to the parameters, replacing the previous values of `0xDEADBEEF` and `0xBABEFACE`. Since both `raspberry::init` and `strawberry::init` invoke markers within their bodies, the `currentStep` value does not increase linearly. The program contains a total of 120 markers, which also sets the value of `maxStep`.

Together, this contributes to a highly accurate progress bar.
