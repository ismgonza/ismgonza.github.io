// Contador de checks por sección en las guías (.pd-acc)
document.querySelectorAll('.pd-acc').forEach(function (acc) {
  var boxes = acc.querySelectorAll('input[type="checkbox"]');
  var badge = acc.querySelector('.pd-count');
  function update() {
    var n = Array.prototype.filter.call(boxes, function (b) { return b.checked; }).length;
    badge.textContent = n + ' / ' + boxes.length;
    acc.classList.toggle('done', n === boxes.length);
  }
  boxes.forEach(function (b) { b.addEventListener('change', update); });
  update();
});
