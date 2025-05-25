// theme-toggle.js
function initThemeToggle() {
  const toggleButton = document.getElementById('theme-toggle');
  if (!toggleButton) return;

  const body = document.body;
  const icon = toggleButton.querySelector('i');
  if (!icon) return;

  // Initial setup
  const savedTheme = localStorage.getItem('theme') || 'dark';
  body.classList.add(savedTheme === 'light' ? 'light-mode' : 'dark');
  icon.className = savedTheme === 'light' ? 'fas fa-sun' : 'fas fa-moon';

  // Click handler
  toggleButton.addEventListener('click', () => {
    const isLight = body.classList.contains('light-mode');
    body.classList.toggle('light-mode', !isLight);
    body.classList.toggle('dark', isLight);
    icon.className = isLight ? 'fas fa-moon' : 'fas fa-sun';
    localStorage.setItem('theme', isLight ? 'dark' : 'light');
  });
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initThemeToggle);
} else {
  initThemeToggle();
}
      // Hamburger menu functionality
      const hamburgerBtn = document.getElementById('hamburger-btn');
      const navLinks = document.getElementById('navLinks');

      hamburgerBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        hamburgerBtn.classList.toggle('active');
        navLinks.classList.toggle('show');
      });
      
      // Close menu when clicking on a link
      document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
          hamburgerBtn.classList.remove('active');
          navLinks.classList.remove('show');
        });
      });

      // Close menu when clicking outside
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.navbar') && window.innerWidth <= 992) {
          hamburgerBtn.classList.remove('active');
          navLinks.classList.remove('show');
        }
      });