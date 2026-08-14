/*
 * ============================================================
 * AIRLOCK AI
 * Frontend Controller
 * ============================================================
 *
 * Responsibilities:
 *
 * 1. Read the user's prompt
 * 2. Send it to Flask
 * 3. Display loading state
 * 4. Display security scan results
 * 5. Display sanitized prompt
 * 6. Display Gemini response
 * 7. Display locally restored final response
 *
 * IMPORTANT:
 *
 * This frontend does NOT call Gemini directly.
 *
 * Browser
 *    ↓
 * Flask
 *    ↓
 * Airlock Privacy Engine
 *    ↓
 * Gemini
 *
 * The Gemini API key therefore never belongs in this file.
 */


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

const promptInput =
    document.getElementById("promptInput");

const secureButton =
    document.getElementById("secureButton");

const characterCount =
    document.getElementById("characterCount");

const loadingSection =
    document.getElementById("loadingSection");

const loadingText =
    document.getElementById("loadingText");

const errorSection =
    document.getElementById("errorSection");

const errorMessage =
    document.getElementById("errorMessage");

const securitySection =
    document.getElementById("securitySection");

const protectedCount =
    document.getElementById("protectedCount");

const modelName =
    document.getElementById("modelName");

const processingTime =
    document.getElementById("processingTime");

const policyBadge =
    document.getElementById("policyBadge");

const protectedItems =
    document.getElementById("protectedItems");

const sanitizedSection =
    document.getElementById("sanitizedSection");

const sanitizedPrompt =
    document.getElementById("sanitizedPrompt");

const llmSection =
    document.getElementById("llmSection");

const llmResponse =
    document.getElementById("llmResponse");

const finalSection =
    document.getElementById("finalSection");

const finalResponse =
    document.getElementById("finalResponse");


/* ============================================================
   CONFIGURATION
   ============================================================ */

const SECURE_CHAT_ENDPOINT =
    "/api/v1/secure-chat";


/* ============================================================
   CHARACTER COUNTER
   ============================================================ */

function updateCharacterCount() {

    const length =
        promptInput.value.length;

    characterCount.textContent =
        `${length} character${length === 1 ? "" : "s"}`;
}


promptInput.addEventListener(
    "input",
    updateCharacterCount
);


/* ============================================================
   RESET RESULT SECTIONS
   ============================================================ */

function resetResults() {

    securitySection.classList.add("hidden");

    sanitizedSection.classList.add("hidden");

    llmSection.classList.add("hidden");

    finalSection.classList.add("hidden");

    errorSection.classList.add("hidden");

    protectedItems.innerHTML = "";

    sanitizedPrompt.textContent = "";

    llmResponse.textContent = "";

    finalResponse.textContent = "";

}


/* ============================================================
   LOADING STATE
   ============================================================ */

function showLoading(message) {

    loadingText.textContent = message;

    loadingSection.classList.remove("hidden");

    secureButton.disabled = true;

}


function hideLoading() {

    loadingSection.classList.add("hidden");

    secureButton.disabled = false;

}


/* ============================================================
   ERROR HANDLING
   ============================================================ */

function showError(message) {

    errorMessage.textContent =
        message;

    errorSection.classList.remove("hidden");

}


function hideError() {

    errorSection.classList.add("hidden");

}


/* ============================================================
   SECURITY ITEMS
   ============================================================ */

function displayProtectedItems(items) {

    protectedItems.innerHTML = "";

    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {

        const emptyMessage =
            document.createElement("span");

        emptyMessage.className =
            "protected-item";

        emptyMessage.textContent =
            "No sensitive information detected";

        protectedItems.appendChild(
            emptyMessage
        );

        return;
    }


    items.forEach(function (item) {

        const container =
            document.createElement("div");

        container.className =
            "protected-item";


        const token =
            document.createElement("span");

        token.textContent =
            item.token || "PROTECTED";


        const type =
            document.createElement("span");

        type.className =
            "protected-item-type";

        type.textContent =
            item.type
                ? `(${item.type})`
                : "";


        container.appendChild(token);

        container.appendChild(type);

        protectedItems.appendChild(
            container
        );

    });

}


/* ============================================================
   DISPLAY SECURITY RESULT
   ============================================================ */

function displaySecurityResult(data) {

    securitySection.classList.remove(
        "hidden"
    );


    /*
     * Number of protected items
     */

    protectedCount.textContent =
        data.metadata &&
        typeof data.metadata.protected_count === "number"
            ? data.metadata.protected_count
            : 0;


    /*
     * Gemini model
     */

    modelName.textContent =
        data.metadata &&
        data.metadata.model
            ? data.metadata.model
            : "Gemini";


    /*
     * Processing time
     */

    if (
        data.metadata &&
        data.metadata.processing_time_ms !== undefined
    ) {

        processingTime.textContent =
            `${data.metadata.processing_time_ms} ms`;

    } else {

        processingTime.textContent =
            "-";

    }


    /*
     * Policy
     */

    if (
        data.policy &&
        data.policy.decision
    ) {

        policyBadge.textContent =
            String(
                data.policy.decision
            ).toUpperCase();

    } else {

        policyBadge.textContent =
            "SANITIZED";

    }


    /*
     * Protected information
     */

    displayProtectedItems(
        data.protected_items
    );

}


/* ============================================================
   DISPLAY SANITIZED PROMPT
   ============================================================ */

function displaySanitizedPrompt(
    prompt
) {

    sanitizedSection.classList.remove(
        "hidden"
    );

    sanitizedPrompt.textContent =
        prompt || "";

}


/* ============================================================
   DISPLAY GEMINI RESPONSE
   ============================================================ */

function displayLLMResponse(
    response
) {

    llmSection.classList.remove(
        "hidden"
    );

    llmResponse.textContent =
        response || "";

}


/* ============================================================
   DISPLAY FINAL RESPONSE
   ============================================================ */

function displayFinalResponse(
    response
) {

    finalSection.classList.remove(
        "hidden"
    );

    finalResponse.textContent =
        response || "";

}


/* ============================================================
   SEND PROMPT TO AIRLOCK
   ============================================================ */

async function securePrompt() {

    const prompt =
        promptInput.value.trim();


    /*
     * Validate prompt
     */

    if (!prompt) {

        showError(
            "Please enter a prompt first."
        );

        promptInput.focus();

        return;
    }


    /*
     * Reset previous results
     */

    resetResults();

    hideError();


    /*
     * Start loading
     */

    showLoading(
        "Scanning locally for sensitive information..."
    );


    try {

        /*
         * ----------------------------------------------------
         * Step 1
         *
         * Send prompt to Flask.
         * ----------------------------------------------------
         */

        const response =
            await fetch(
                SECURE_CHAT_ENDPOINT,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify(
                        {
                            prompt: prompt
                        }
                    )
                }
            );


        /*
         * ----------------------------------------------------
         * Step 2
         *
         * Try to parse JSON.
         * ----------------------------------------------------
         */

        let data;

        try {

            data =
                await response.json();

        } catch (jsonError) {

            throw new Error(
                "The server returned an invalid response."
            );

        }


        /*
         * ----------------------------------------------------
         * Step 3
         *
         * Handle HTTP errors.
         * ----------------------------------------------------
         */

        if (!response.ok) {

            throw new Error(
                data.error ||
                data.message ||
                `Server error (${response.status})`
            );

        }


        /*
         * ----------------------------------------------------
         * Step 4
         *
         * Verify successful Airlock response.
         * ----------------------------------------------------
         */

        if (!data.success) {

            throw new Error(
                data.error ||
                "Airlock could not process the prompt."
            );

        }


        /*
         * ----------------------------------------------------
         * Step 5
         *
         * Update loading message.
         * ----------------------------------------------------
         */

        showLoading(
            "Sensitive information protected. Sending safe prompt to Gemini..."
        );


        /*
         * Small delay so the security workflow is visually
         * understandable during the demo.
         */

        await sleep(250);


        /*
         * ----------------------------------------------------
         * Step 6
         *
         * Display security information.
         * ----------------------------------------------------
         */

        displaySecurityResult(
            data
        );


        /*
         * ----------------------------------------------------
         * Step 7
         *
         * Display sanitized prompt.
         * ----------------------------------------------------
         */

        displaySanitizedPrompt(
            data.sanitized_prompt
        );


        /*
         * ----------------------------------------------------
         * Step 8
         *
         * Display Gemini response.
         * ----------------------------------------------------
         */

        displayLLMResponse(
            data.llm_response
        );


        /*
         * ----------------------------------------------------
         * Step 9
         *
         * Display final locally restored response.
         * ----------------------------------------------------
         */

        displayFinalResponse(
            data.final_response
        );


        /*
         * Scroll to final answer.
         */

        finalSection.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });


    } catch (error) {

        console.error(
            "Airlock request failed:",
            error
        );


        showError(
            error.message ||
            "Unable to connect to Airlock."
        );


    } finally {

        hideLoading();

    }

}


/* ============================================================
   BUTTON EVENT
   ============================================================ */

secureButton.addEventListener(
    "click",
    securePrompt
);


/* ============================================================
   KEYBOARD SHORTCUT
   ============================================================ */

promptInput.addEventListener(
    "keydown",
    function (event) {

        /*
         * Cmd + Enter on Mac
         *
         * Ctrl + Enter on Windows/Linux
         */

        if (
            event.key === "Enter" &&
            (event.metaKey || event.ctrlKey)
        ) {

            event.preventDefault();

            securePrompt();

        }

    }
);


/* ============================================================
   UTILITY
   ============================================================ */

function sleep(milliseconds) {

    return new Promise(
        function (resolve) {

            setTimeout(
                resolve,
                milliseconds
            );

        }
    );

}


/* ============================================================
   INITIALIZATION
   ============================================================ */

updateCharacterCount();

console.log(
    "Airlock AI frontend initialized."
);