import axios from "axios";
import Constants from "../utils/constants";

const API_ROOT_URL = Constants.API_ROOT_URL;
const API_PORT = Constants.API_PORT;

export default {
  login(username, password) {
    return axios
      .post(`${API_ROOT_URL}:${API_PORT}/api/login/`, {
        username: username,
        password: password,
      })
      .then((result) => result.data.token)
      .then((result) => {
        return result;
      })
      .catch((error) => {
        console.log(error);
        return error.response.status;
      });
  },
  fetchScanSettings(config) {
    return axios
      .get(`${API_ROOT_URL}:${API_PORT}/api/scan-settings`, config)
      .then((result) => {
        return result.data;
      })
      .catch((error) => {
        console.log(error);
      });
  },
  updateScanSettings(config, isSoftware, isHardware) {
    let data = {
      'is_scan_software': isSoftware ? "True" : "False",
      'is_scan_hardware': isHardware ? "True" : "False",
    };
    console.log(data);
    return axios
      .post(`${API_ROOT_URL}:${API_PORT}/api/scan-settings`, data, config)
      .then((result) => {
        return result.status;
      })
      .catch((error) => {
        console.log(error);
      });
  },
  async fetchScanStatus(config) {
    return axios
      .get(`${API_ROOT_URL}:${API_PORT}/api/get_status`, config)
      .then((result) => {
        return result;
      })
      .catch((error) => {
        console.log(error);
      });
  }, async sync_db(config) {
    return axios
      .get(`${API_ROOT_URL}:${API_PORT}/api/sync-db`, config)
      .then((result) => {
        return result;
      })
      .catch((error) => {
        console.log(error);
      });
  },
};
