// history.js - search filter only

function filterTable() {
    var input = document.getElementById('searchBox').value.toLowerCase();
    var rows = document.querySelectorAll('#historyBody tr');

    rows.forEach(function(row) {
        var urlCell = row.querySelector('.url-cell');
        if (urlCell) {
            var url = urlCell.getAttribute('data-url').toLowerCase();
            row.style.display = url.includes(input) ? '' : 'none';
        }
    });
}