#ifndef NL_PROGRESSBAR_HPP
#define NL_PROGRESSBAR_HPP

namespace progressbar
{
    typedef unsigned int step_value_t;

    constexpr const step_value_t UNDEFINED_CURRENT_STEP = 0xDEADBEEF;
    constexpr const step_value_t UNDEFINED_MAX_STEP = 0xBABEFACE;

    typedef void (__stdcall* handler_t)(step_value_t currentStep, step_value_t maxStep);

    extern handler_t g_progressbarHandler;

    void SetProgressbarHandler(handler_t progressbarHandler);
    void __declspec(noinline) __fastcall Marker(step_value_t currentStep = UNDEFINED_CURRENT_STEP, step_value_t maxStep = UNDEFINED_MAX_STEP);
};

#define PROGRESSBAR_MARKER progressbar::Marker();

#endif
