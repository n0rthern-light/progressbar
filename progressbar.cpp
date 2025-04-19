#include "progressbar.hpp"

namespace progressbar {
    handler_t g_progressbarHandler = nullptr;

    void SetProgressbarHandler(handler_t progressbarHandler)
    {
        g_progressbarHandler = progressbarHandler;
    }

    void __declspec(noinline) __fastcall Marker(step_value_t currentStep, step_value_t maxStep)
    {
        if (!g_progressbarHandler) {
            return;
        }

        if (currentStep == UNDEFINED_CURRENT_STEP || maxStep == UNDEFINED_MAX_STEP) {
            return;
        }

        if (!maxStep) {
            return;
        }

        if (currentStep > maxStep) {
            return;
        }

        g_progressbarHandler(currentStep, maxStep);
    }
};
