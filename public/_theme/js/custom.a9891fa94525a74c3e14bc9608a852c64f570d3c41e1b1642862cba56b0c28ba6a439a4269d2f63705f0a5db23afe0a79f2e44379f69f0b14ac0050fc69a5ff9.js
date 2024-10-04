document.addEventListener("DOMContentLoaded", function() {
  document.body.innerHTML = document.body.innerHTML.replace(/\+(.*?)\+/g, function(match, p1) {
      return '<span class="underline-bold">' + p1 + '</span>';
  });
});
