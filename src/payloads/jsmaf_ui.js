// Simple UI - Interactive Navigation Demo
// Can be injected via: jsmaf.eval(code) or include("simple_ui.js")

(function() {
    // Clear screen
    jsmaf.root.children.length = 0;

    // State
    var currentButton = 0;
    var buttons = [];
    var buttonTexts = [];

    // Button images
    var normalButtonImg = "file:///assets/img/button_9.png";
    var selectedButtonImg = "file:///assets/img/button_over_9.png";

    // Background
    var background = new Image({
        url: "file:///assets/img/bg_blue.png",
        x: 0,
        y: 0,
        width: 1920,
        height: 1080
    });
    jsmaf.root.children.push(background);

    // Logo
    var logo = new Image({
        url: "file:///assets/img/cobra_logo_full.png",
        x: 760,  // (1920-400)/2
        y: 200,
        width: 400,
        height: 100
    });
    jsmaf.root.children.push(logo);

    // Button 1 - "Continue"
    var button1 = new Image({
        url: normalButtonImg,
        x: 660,
        y: 450,
        width: 300,
        height: 80
    });
    buttons.push(button1);
    jsmaf.root.children.push(button1);

    // Button 1 Text
    var text1 = new Text({
        x: 680,
        y: 480,
        width: 260,
        height: 40,
        text: "lapse+binloader",
        color: "rgb(255,255,255)",
        fontSize: 22
    });
    buttonTexts.push(text1);
    jsmaf.root.children.push(text1);

    // Button 2 - "Settings"
    var button2 = new Image({
        url: normalButtonImg,
        x: 960,
        y: 450,
        width: 300,
        height: 80
    });
    buttons.push(button2);
    jsmaf.root.children.push(button2);

    // Button 2 Text
    var text2 = new Text({
        x: 1050,
        y: 480,
        width: 120,
        height: 40,
        text: "exit",
        color: "rgb(255,255,255)",
        fontSize: 24
    });
    buttonTexts.push(text2);
    jsmaf.root.children.push(text2);

    // Button 3 - "Exit"
    var button3 = new Image({
        url: normalButtonImg,
        x: 810,
        y: 600,
        width: 300,
        height: 80
    });
    buttons.push(button3);
    jsmaf.root.children.push(button3);

    // Button 3 Text
    var text3 = new Text({
        x: 890,
        y: 630,
        width: 140,
        height: 40,
        text: "UwU",
        color: "rgb(255,255,255)",
        fontSize: 24
    });
    buttonTexts.push(text3);
    jsmaf.root.children.push(text3);

    // Info text at bottom
    var infoText = new Text({
        x: 660,
        y: 900,
        width: 600,
        height: 40,
        text: "Use Arrow Keys or D-Pad to Navigate",
        color: "rgb(170,170,170)",
        fontSize: 20
    });
    jsmaf.root.children.push(infoText);

    // Update highlight
    function updateHighlight() {
        for (var i = 0; i < buttons.length; i++) {
            if (i === currentButton) {
                buttons[i].url = selectedButtonImg;
                buttons[i].alpha = 1.0;
                buttonTexts[i].color = "rgb(255,255,255)";
                buttonTexts[i].alpha = 1.0;
            } else {
                buttons[i].url = normalButtonImg;
                buttons[i].alpha = 0.4;  // Dim unselected buttons
                buttonTexts[i].color = "rgb(200,200,200)";
                buttonTexts[i].alpha = 0.6;  // Dim unselected text
            }
        }
        log("Selected button: " + currentButton);
    }

    // Keyboard handler
    jsmaf.onKeyDown = function(keyCode) {
        log("Key pressed: " + keyCode);

        // D-Pad Right (5)
        if (keyCode === 5) {
            currentButton = (currentButton + 1) % buttons.length;
            updateHighlight();
        }
        // D-Pad Left (7)
        else if (keyCode === 7) {
            currentButton = (currentButton - 1 + buttons.length) % buttons.length;
            updateHighlight();
        }
        // D-Pad Down (6)
        else if (keyCode === 6) {
            currentButton = (currentButton + 1) % buttons.length;
            updateHighlight();
        }
        // D-Pad Up (4)
        else if (keyCode === 4) {
            currentButton = (currentButton - 1 + buttons.length) % buttons.length;
            updateHighlight();
        }
        // X button (enter/select) - 14
        else if (keyCode === 14) {
            handleButtonPress();
        }
        // Circle button (back) - 13
        else if (keyCode === 13) {
            alert("Back pressed!");
        }
    };

    // Handle button activation
    function handleButtonPress() {
        if (currentButton === 0) {
            // lapse+binloader
            log("Loading loader.js...");
            include("loader.js");
        } else if (currentButton === 1) {
            // exit
            log("Exiting application...");
            jsmaf.exit();
        } else if (currentButton === 2) {
            // UwU
            alert("UwU");
        }
    }

    // Initialize first button as selected
    updateHighlight();

    log("Interactive UI loaded!");
    log("Total elements: " + jsmaf.root.children.length);
    log("Buttons: " + buttons.length);
    log("Use arrow keys to navigate, Enter/X to select");
})();
