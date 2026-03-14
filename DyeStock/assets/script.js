function openModal(id) { document.getElementById(id).style.display = 'block'; document.body.style.overflow = 'hidden'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; document.body.style.overflow = 'auto'; }
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        closeModal(event.target.id);
        document.body.style.overflow = 'auto';
    }
};
