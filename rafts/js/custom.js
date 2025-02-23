console.log("Script starting...");

document.addEventListener("DOMContentLoaded", function() {
    console.log("DOM loaded, starting text processing...");
    
    // Test with a simple alert to ensure the script runs
    const testText = document.createElement('div');
    testText.textContent = "Script is running";
    testText.style.position = "fixed";
    testText.style.top = "0";
    testText.style.right = "0";
    testText.style.background = "red";
    testText.style.padding = "10px";
    document.body.appendChild(testText);

    // Function to recursively process each text node
    function replaceSymbolsWithFormatting(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            console.log("Processing text node:", node.textContent);
            var replacedText = node.textContent
                .replace(/\+(.*?)\+/g, function(match, p1) {
                    console.log("Found match:", match);
                    var span = document.createElement('span');
                    span.className = 'underline-bold';
                    span.textContent = p1;
                    return span.outerHTML;
                });

            if (replacedText !== node.textContent) {
                var tempDiv = document.createElement('div');
                tempDiv.innerHTML = replacedText;
                while (tempDiv.firstChild) {
                    node.parentNode.insertBefore(tempDiv.firstChild, node);
                }
                node.remove();
            }
        } else {
            // If it's not a text node, recursively process children
            Array.from(node.childNodes).forEach(replaceSymbolsWithFormatting);
        }
    }

    // Start processing from the body
    console.log("Starting to process body"); // Debug log
    Array.from(document.body.childNodes).forEach(replaceSymbolsWithFormatting);
    console.log("Finished processing body"); // Debug log
    console.log("Text processing complete");
}); 