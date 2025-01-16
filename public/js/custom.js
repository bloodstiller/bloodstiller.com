document.addEventListener("DOMContentLoaded", function() {
    console.log("Custom.js loaded"); // Debug log

    // Function to recursively process each text node
    function replaceSymbolsWithFormatting(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            // Debug log
            if (node.textContent.includes('+')) {
                console.log("Found text with plus:", node.textContent);
            }

            // Replace text between + and = with spans
            var replacedText = node.textContent
                .replace(/\+([^+]+)\+/g, function(match, p1) { // Modified regex
                    console.log("Replacing:", match, "with content:", p1); // Debug log
                    var span = document.createElement('span');
                    span.className = 'underline-bold';
                    span.textContent = p1;
                    return span.outerHTML;
                });

            if (replacedText !== node.textContent) {
                console.log("Text was replaced:", replacedText); // Debug log
                // Replace the node's content with processed HTML
                var tempDiv = document.createElement('div');
                tempDiv.innerHTML = replacedText;
                while (tempDiv.firstChild) {
                    node.parentNode.insertBefore(tempDiv.firstChild, node);
                }
                node.remove(); // Remove the original text node
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
}); 