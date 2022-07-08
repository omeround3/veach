<template>
  <div class="py-4 container-fluid">
    <div class="row mb-4">
      <div class="col-lg-12 position-relative z-index-2">
        <div class="row mt-4">
          <div class="col-lg-3 col-md-3 col-sm-3">
            <mini-statistics-card :title="totalCVERecordsCard" />
          </div>
          <div class="col-lg-3 col-md-3 col-sm-3">
            <mini-statistics-card :title="totalCPERecordsCard" />
          </div>
          <div class="col-lg-3 col-md-3 col-sm-3">
            <mini-statistics-card :title="totalCategoriesCard" />
          </div>
          <div class="col-lg-3 col-md-3 col-sm-3">
            <mini-statistics-card :title="totalVulnerabilitiesCard" />
          </div>
          <div class="row mt-4">
            <div class="col-lg-12 col-md-12">
              <div class="d-grid gap-2" style="height: 100%">
                <button type="button" name="" id="" class="btn btn-veach-red" style="font-size: 40px" @click="scan">
                  {{ buttonText }}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12 col-md-12 mb-md-0 mb-4">
        <project-card title="Categories" description=""
          :headers="['Category\nvector', 'attack\ncomplexity', 'confidentiality\nimpact', 'integrity\nimpact', 'availability\nimpact', 'average\nscore', 'number\nof cve\'s']"
          :projects="totalCategories" style="" />
      </div>
    </div>
  </div>
</template>
<script>
import axios from "axios";
import MiniStatisticsCard from "./components/MiniStatisticsCard.vue";
import ProjectCard from "./components/ProjectCard.vue";
// import userState from "@/store/user-state";
// import api from "@/api/veach-api";
import Constants from "../utils/constants";

const API_ROOT_URL = Constants.API_ROOT_URL;
const API_PORT = Constants.API_PORT;

export default {
  name: "dashboard-default",
  data() {
    return {
      buttonText: null,
      token: null,
      status: null,
      totalCVERecordsCard: {},
      totalCPERecordsCard: {},
      totalCategoriesCard: {},
      totalVulnerabilitiesCard: {},
      totalCategories: [],
      vectorLegend: {
        L: "Local",
        N: "Network",
        P: "Physical",
        A: "Adjacent Network",
      },
      levelLegend: {
        N: "None",
        L: "Low",
        H: "High",
      },
      config: {
        headers: {
          'Accept': "application/json",
          'Authorization': `Token ${window.localStorage.getItem("token")}`,
        },
      },
    };

  },
  async created() {
    this.token = window.localStorage.getItem("token");
    console.log(`Dashboard::Token ${this.token}`);
    this.totalCategoriesCard = {
      text: "Total Vulnerabilities Categories",
      value: "-",
    };
    this.totalVulnerabilitiesCard = {
      text: "Total Vulnerabilities On This Machine",
      value: "-",
    };
    this.getTotalCVERecords();
    this.getTotalCPERecords();
    this.getCveCategories();
  },
  mounted() {
    this.getStatus();
    this.timer = setInterval(() => {
      this.getStatus();
      if (this.status === "scanning") {
        this.getCveCategories()
      }
      if (this.totalCPERecordsCard.value === "-") {
        this.getTotalCPERecords()
      }
    }, 5000);
  },
  beforeUnmount() {
    clearInterval(this.timer);
  },
  methods: {
    async getStatus() {
      var element = this;
      const res = await axios.get(
        `${API_ROOT_URL}:${API_PORT}/api/get_status`,
        this.config
      );
      if (res) {
        console.log(res);
        element.status = res.data["status"];
        if (element.status === "scanning") {
          element.buttonText = "SCANNING - CLICK TO STOP"
        } else if (element.status === "stopped") {
          element.buttonText = "SCAN STOPPED - CLICK TO START AGAIN"

        } else if (element.status === "finished") {
          element.buttonText = "SCAN COMPLETED - CLICK TO START AGAIN"

        } else if (element.status === "new") {
          element.buttonText = "START NEW SCAN"
        }
      }
    },
    async getTotalCVERecords() {
      this.totalCVERecordsCard = {
        text: "Total CVE Records In DB",
        value: "-",
      };
      const res = await axios.get(
        `${API_ROOT_URL}:${API_PORT}/api/cve_db_info`,
        this.config
      );
      if (res) {
        this.totalCVERecordsCard.value = Number(res.data.size).toLocaleString();
      }
    },
    async getTotalCPERecords() {
      this.totalCPERecordsCard = {
        text: "Total Components Installed",
        value: "-",
        data: [],
      };
      const res = await axios.get(
        `${API_ROOT_URL}:${API_PORT}/api/num_of_components`,
        this.config
      );
      if (res) {
        if (res.data.num !== 0) {
          this.totalCPERecordsCard.value = Number(res.data.num).toLocaleString();
        }
      }
    },
    async scan() {
      this.buttonText = "..."
      var element = this
      if (this.status === "new" || this.status === "finished" || this.status === "stopped") {
        this.totalCategories = [];
        this.isScanning = true;
        // var element = this
        await axios
          .get(`${API_ROOT_URL}:${API_PORT}/api/start_scan`, this.config)
          .then(function (res) {
            if (res.status == 200) {
              element.getStatus()
            }
          });
      } else {
        this.isScanning = false;
        await axios
          .get(`${API_ROOT_URL}:${API_PORT}/api/stop_scan`, this.config)
          .then(function (res) {
            if (res.status != 200) {
              element.getStatus()
            }
          });
      }
    },
    async getCveCategories() {
      var element = this;
      await axios
        .get(`${API_ROOT_URL}:${API_PORT}/api/cve_categories`, this.config)
        .then(function (res) {
          if (res.status == 200) {
            let totalCategories = [];
            let numOfCVERecordsFound = 0;
            let numOfCategoriesFound = 0;
            Object.values(res.data).forEach((category) => {
              if (category.affected_records.length > 0) {
                numOfCVERecordsFound += category.affected_records.length;
                numOfCategoriesFound++;
                let data = {
                  vector:
                    element.vectorLegend[
                    category.record_scheme.vector_string_attributes.AV
                    ],
                  complexity:
                    element.levelLegend[
                    category.record_scheme.vector_string_attributes.AC
                    ],
                  confidentiality: element.levelLegend[
                    category.record_scheme.vector_string_attributes.C
                  ],
                  integrity: element.levelLegend[
                    category.record_scheme.vector_string_attributes.I
                  ],
                  availability: element.levelLegend[
                    category.record_scheme.vector_string_attributes.A
                  ],
                  score: category.average,
                  size: category.affected_records.length,
                  string: category.record_scheme.vector_string.replaceAll(
                    "/",
                    "-"
                  ),
                  critical: category.is_critical,
                };
                totalCategories.push(data);
              }
            });
            totalCategories.sort((a, b) =>
              a.score < b.score ? 1 : -1
            );
            element.totalCategories = totalCategories
            if (numOfCategoriesFound !== 0) {
              element.totalCategoriesCard.value = Number(
                numOfCategoriesFound
              ).toLocaleString();
            }
            if (numOfCVERecordsFound !== 0) {
              element.totalVulnerabilitiesCard.value = Number(
                numOfCVERecordsFound
              ).toLocaleString();
            }
          }
        });
    },
  },

  components: {
    MiniStatisticsCard,
    ProjectCard,
  },
};
</script>
