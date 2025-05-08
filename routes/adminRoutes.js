import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './AdminPanels.css';

const AdminPanels = () => {
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState([]);
  const [businesses, setBusinesses] = useState([]);
  const [ledger, setLedger] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Check admin access and fetch initial data
  useEffect(() => {
    const userData = JSON.parse(localStorage.getItem('user'));
    if (!userData || userData.role !== 'admin') {
      navigate('/login');
      return;
    }

    fetchUsers();
    fetchBusinesses();
    fetchLedger();
  }, [navigate]);

  // Fetch all users
  const fetchUsers = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://zangena-e33a7e55637a.herokuapp.com/api/users', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUsers(response.data);
    } catch (err) {
      setError('Failed to fetch users');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch all businesses
  const fetchBusinesses = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://zangena-e33a7e55637a.herokuapp.com/api/business', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setBusinesses(response.data);
    } catch (err) {
      setError('Failed to fetch businesses');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch admin ledger
  const fetchLedger = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://zangena-e33a7e55637a.herokuapp.com/api/admin/ledger', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setLedger(response.data);
    } catch (err) {
      setError('Failed to fetch ledger');
      console.error(err);
    }
  };

  // Handle KYC status update
  const updateKYCStatus = async (id, type, status) => {
    try {
      const token = localStorage.getItem('token');
      const endpoint = type === 'users' ? '/api/users/update-kyc' : '/api/business/update-kyc';
      await axios.post(
        `https://zangena-e33a7e55637a.herokuapp.com${endpoint}`,
        { id, kycStatus: status },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (type === 'users') {
        setUsers(users.map(u => (u._id === id ? { ...u, kycStatus: status } : u)));
      } else {
        setBusinesses(businesses.map(b => (b._id === id ? { ...b, kycStatus: status } : b)));
      }
    } catch (err) {
      setError(`Failed to update KYC status for ${type}`);
      console.error(err);
    }
  };

  // Render user panel
  const renderUserPanel = () => (
    <div className="panel">
      <h2 className="text-2xl font-bold mb-4">User Management</h2>
      {loading && <p>Loading...</p>}
      {error && <p className="text-red-500">{error}</p>}
      <table className="w-full border-collapse">
        <thead>
          <tr className="bg-gray-200">
            <th className="p-2">Username</th>
            <th className="p-2">Phone</th>
            <th className="p-2">Balance</th>
            <th className="p-2">KYC Status</th>
            <th className="p-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map(user => (
            <tr key={user._id} className="border-b">
              <td className="p-2">{user.username}</td>
              <td className="p-2">{user.phoneNumber}</td>
              <td className="p-2">{user.balance} ZMW</td>
              <td className="p-2">{user.kycStatus}</td>
              <td className="p-2">
                <select
                  onChange={e => updateKYCStatus(user._id, 'users', e.target.value)}
                  value={user.kycStatus}
                  className="border p-1 mr-2"
                >
                  <option value="pending">Pending</option>
                  <option value="verified">Verified</option>
                  <option value="rejected">Rejected</option>
                </select>
                <button
                  onClick={() => navigate(`/admin/user/${user._id}`)}
                  className="bg-blue-500 text-white px-2 py-1 rounded"
                >
                  Details
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  // Render business panel
  const renderBusinessPanel = () => (
    <div className="panel">
      <h2 className="text-2xl font-bold mb-4">Business Management</h2>
      {loading && <p>Loading...</p>}
      {error && <p className="text-red-500">{error}</p>}
      <table className="w-full border-collapse">
        <thead>
          <tr className="bg-gray-200">
            <th className="p-2">Business ID</th>
            <th className="p-2">Name</th>
            <th className="p-2">Balance</th>
            <th className="p-2">KYC Status</th>
            <th className="p-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {businesses.map(business => (
            <tr key={business._id} className="border-b">
              <td className="p-2">{business.businessId}</td>
              <td className="p-2">{business.name}</td>
              <td className="p-2">{business.balance} ZMW</td>
              <td className="p-2">{business.kycStatus}</td>
              <td className="p-2">
                <select
                  onChange={e => updateKYCStatus(business._id, 'businesses', e.target.value)}
                  value={business.kycStatus}
                  className="border p-1 mr-2"
                >
                  <option value="pending">Pending</option>
                  <option value="verified">Verified</option>
                  <option value="rejected">Rejected</option>
                </select>
                <button
                  onClick={() => navigate(`/admin/business/${business._id}`)}
                  className="bg-blue-500 text-white px-2 py-1 rounded"
                >
                  Details
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  // Render ledger panel
  const renderLedgerPanel = () => (
    <div className="panel">
      <h2 className="text-2xl font-bold mb-4">Admin Ledger</h2>
      {ledger ? (
        <div>
          <p>Total Balance: {ledger.totalBalance} ZMW</p>
          <p>Last Updated: {new Date(ledger.lastUpdated).toLocaleString()}</p>
          <h3 className="text-xl font-semibold mt-4">Transactions</h3>
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gray-200">
                <th className="p-2">Type</th>
                <th className="p-2">Amount</th>
                <th className="p-2">Sender</th>
                <th className="p-2">Receiver</th>
                <th className="p-2">Date</th>
              </tr>
            </thead>
            <tbody>
              {ledger.transactions.map(tx => (
                <tr key={tx._id || tx.date} className="border-b">
                  <td className="p-2">{tx.type}</td>
                  <td className="p-2">{tx.amount} ZMW</td>
                  <td className="p-2">{tx.sender}</td>
                  <td className="p-2">{tx.receiver}</td>
                  <td className="p-2">{new Date(tx.date).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>Loading ledger...</p>
      )}
    </div>
  );

  return (
    <div className="admin-container p-4">
      <script src="https://cdn.tailwindcss.com"></script>
      <h1 className="text-3xl font-bold mb-6">Zangena Admin Dashboard</h1>
      <div className="tabs flex mb-4">
        <button
          className={`px-4 py-2 mr-2 ${activeTab === 'users' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
          onClick={() => setActiveTab('users')}
        >
          Users
        </button>
        <button
          className={`px-4 py-2 mr-2 ${activeTab === 'businesses' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
          onClick={() => setActiveTab('businesses')}
        >
          Businesses
        </button>
        <button
          className={`px-4 py-2 ${activeTab === 'ledger' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
          onClick={() => setActiveTab('ledger')}
        >
          Ledger
        </button>
      </div>
      {activeTab === 'users' && renderUserPanel()}
      {activeTab === 'businesses' && renderBusinessPanel()}
      {activeTab === 'ledger' && renderLedgerPanel()}
    </div>
  );
};

export default AdminPanels;