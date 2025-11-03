let clients = [];

async function loadClients() {
    try {
        const res = await fetch('/api/clients');
        if (!res.ok) return;
        const data = await res.json();
        clients = data;
        renderClients();
    } catch (e) {
        console.error("Не удалось загрузить клиентов:", e);
    }
}

function renderClients() {
    const tbody = document.getElementById('clients-list');
    tbody.innerHTML = '';

    clients.forEach(client => {
        const row = document.createElement('tr');

        const now = new Date();
        const lastSeen = new Date(client.last_connect);
        const diffMs = now - lastSeen;
        const diffMin = Math.floor(diffMs / 60000);

        const isOnline = diffMin <= 5;

        row.innerHTML = `
            <td><input type="checkbox" class="client-checkbox" data-id="${client.id}"></td>
            <td>${client.hostname || 'Unknown'}</td>
            <td>${client.last_archive || '—'}</td>
            <td>${formatTimeAgo(diffMin)}</td>
            <td><span class="status ${isOnline ? 'online' : 'offline'}">
                ${isOnline ? 'Online' : 'Offline'}
            </span></td>
            <td class="actions-btns">
                <button onclick="collect('${client.id}')">Сбор</button>
                <button onclick="run('${client.id}')">Запустить</button>
                <button onclick="download('${client.id}')">Скачать</button>
            </td>
        `;
        tbody.appendChild(row);
    });

    updateSelectedCount();
}

function formatTimeAgo(minutes) {
    if (minutes < 1) return 'только что';
    if (minutes === 1) return '1 мин назад';
    if (minutes < 60) return `${minutes} мин назад`;
    const hours = Math.floor(minutes / 60);
    return `${hours} ч назад`;
}

function updateSelectedCount() {
    const count = document.querySelectorAll('.client-checkbox:checked').length;
    document.getElementById('selected-count').textContent = count;
}

function collect(clientId) {
    alert(`Сбор запущен для ${clientId}`);
    // TODO: fetch('/api/command', { method: 'POST', body: JSON.stringify({ id: clientId, cmd: 'collect' }) })
}

function run(clientId) {
    alert(`Запуск на ${clientId}`);
    // TODO: отправить команду через API
}

function download(clientId) {
    window.open(`/download/${clientId}`, '_blank');
}

setInterval(loadClients, 5000);

document.getElementById('select-all').addEventListener('change', function() {
    const checked = this.checked;
    document.querySelectorAll('.client-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    updateSelectedCount();
});

document.addEventListener('change', function(e) {
    if (e.target.classList.contains('client-checkbox')) {
        updateSelectedCount();
    }
});

loadClients();