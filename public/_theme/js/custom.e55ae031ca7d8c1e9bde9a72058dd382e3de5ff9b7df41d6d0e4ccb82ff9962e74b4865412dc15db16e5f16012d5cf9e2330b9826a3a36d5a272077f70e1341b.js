document.addEventListener("DOMContentLoaded", function() {
  // Function to recursively process each text node
  function replaceSymbolsWithFormatting(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      // Replace text between + and = with spans
      var replacedText = node.textContent
        .replace(/\+(.*?)\+/g, function(match, p1) {
          var span = document.createElement('span');
          span.className = 'underline-bold'; // Class for text between +
          span.textContent = p1;
          return span.outerHTML;
        })
      /*
        .replace(/=(.*?)=/g, function(match, p1) {
          var span = document.createElement('span');
          span.className = 'custom-format'; // Class for text between =
          span.textContent = p1;
          return span.outerHTML;
        });
*/
      // Replace the node's content with processed HTML
      var tempDiv = document.createElement('div');
      tempDiv.innerHTML = replacedText;
      while (tempDiv.firstChild) {
        node.parentNode.insertBefore(tempDiv.firstChild, node);
      }
      node.remove(); // Remove the original text node
    } else {
      // If it's not a text node, recursively process children
      node.childNodes.forEach(replaceSymbolsWithFormatting);
    }
  }

  // Start processing from the body
  document.body.childNodes.forEach(replaceSymbolsWithFormatting);
});
