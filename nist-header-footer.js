/**
 * @file
 * Header and footer scripts
 *
 */

document.addEventListener('DOMContentLoaded', function () {

  const cache = "?_=" + new Date().valueOf();

  var headerDiv = document.createElement("div");
  headerDiv.id = 'nistheadergoeshere';
  document.body.prepend(headerDiv);
  var headerRequest = new XMLHttpRequest();
  headerRequest.onreadystatechange = function() {
    if (this.readyState == XMLHttpRequest.DONE &&
        this.status == 200) {
      document.getElementById('nistheadergoeshere').innerHTML =
          this.responseText;
    }
  };
  headerRequest.open('GET', 'https://pages.nist.gov/macos_security/' +
      'boilerplate-header.html' + cache);
  headerRequest.send();

  var footerDiv = document.createElement("div");
  footerDiv.id = 'nistfootergoeshere';
  document.body.append(footerDiv);
  var footerRequest = new XMLHttpRequest();
  footerRequest.onreadystatechange = function() {
    if (this.readyState == XMLHttpRequest.DONE &&
        this.status == 200) {
      document.getElementById('nistfootergoeshere').innerHTML =
          this.responseText;
    }
  };
  footerRequest.open('GET', 'https://pages.nist.gov/macos_security/' +
      'boilerplate-footer.html' + cache);
  footerRequest.send();

});
