document.addEventListener("DOMContentLoaded", function() {
  // Function to recursively process each text node
  function replacePlusWithBoldUnderline(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      var replacedText = node.textContent.replace(/\+(.*?)\+/g, function(match, p1) {
        // Create a span element for bold/underline
        var span = document.createElement('span');
        span.className = 'underline-bold';
        span.textContent = p1;
        return span.outerHTML;
      });

      // Replace the node's content with processed HTML
      var tempDiv = document.createElement('div');
      tempDiv.innerHTML = replacedText;
      while (tempDiv.firstChild) {
        node.parentNode.insertBefore(tempDiv.firstChild, node);
      }
      node.remove(); // Remove the original text node
    } else {
      // If it's not a text node, recursively process children
      node.childNodes.forEach(replacePlusWithBoldUnderline);
    }
  }

  // Start processing from the body
  document.body.childNodes.forEach(replacePlusWithBoldUnderline);
});
