<template>
  <div class="container-fluid py-4">
    <div class="row">
      <div class="col-12">
        <div class="card my-4">
          <div class="card-header p-0 position-relative mt-n4 mx-3 z-index-2 mx-auto" style="width: 60%;">
            <div class="bg-veach-red shadow-warning border-radius-lg pt-4 pb-3">
              <h6 class="text-white text-capitalize ps-3" style="white-space: pre-wrap;">These CVEs (Common
                Vulnerabilities and Exposures) Were Found On Your Machine.<br />
                It means That {{ category.tag }}</h6>
            </div>
          </div>
          <div class="card-body px-0 pb-2">
            <div class="table-responsive p-0">
              <table class="table align-items-center justify-content-center mb-0">
                <thead>
                  <tr>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      CVE
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Score
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Product
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Mitigation
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(
                {
                id,
                score,
                product,
                mitigate,
                cpe,
              },
                index
              ) of records" :key="index">
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm"><a :href="'https://www.cvedetails.com/cve/' + id">{{ id }}</a></h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ score }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ product }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <button v-if="mitigate === ''" type="button" @click="getMitigation(cpe)" name="" id=""
                          class="btn btn-success" :class="{ 'disabled': status == 'scanning' }"
                          style="width: 250px;">MITIGATE</button>
                        <button v-else-if="mitigate === 'NO MITIGATION FOUND'" type="button" name="" id=""
                          class="btn btn-danger" style="width: 250px;">{{ mitigate }}</button>
                        <button v-else type="button" name="" id="" class="btn btn-info"
                          style="white-space: pre-wrap;width: 250px;">{{
                              mitigate
                          }}</button>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import Constants from "../utils/constants";
import api from "@/api/veach-api";

const API_ROOT_URL = Constants.API_ROOT_URL;
const API_PORT = Constants.API_PORT;

export default {
  name: "tables",
  data() {
    return {
      status: "scanning",
      id: null,
      category: {},
      records: [],
      category_id: null,
      config: {
        headers: {
          'Accept': "application/json",
          'Authorization': `Token ${window.localStorage.getItem("token")}`,
        },
      },
      token: null,
    }
  },
  created() {
    this.token = window.localStorage.getItem("token");
    this.id = this.$route.params.id
    this.id = this.id.replaceAll("-", "/")
    this.getCategory(this.id)

  },
  mounted() {
    this.timer = setInterval(() => {
      if (this.id) {
        this.getCategory(this.id)
        this.getStatus();
      }
    }, 1000);
  },
  beforeUnmount() {
    clearInterval(this.timer);
  },
  methods:
  {
    async getStatus() {
      const res = await api.fetchScanStatus(this.config)
      if (res) {
        this.status = res.data["status"];
      }
    },
    async getMitigation(cpe) {
      var element = this
      this.records.forEach(record => {
        if (record.cpe === cpe) {
          record.mitigate = "..."
        }
      })
      const res = await axios.post(`${API_ROOT_URL}:${API_PORT}/api/mitigate`, { "cpe23Uri": cpe }, this.config)
      if (res) {
        if (res.data !== null) {
          var mitigation_string = ''
          for (let [key, value] of Object.entries(res.data)) {

            if (value) {
              let average = 0
              value.forEach(category => {
                // if (category.record_scheme.vector_string === element.category_id) {
                average += category.average
                // }
              })
              // if (average < this.category.average) {
              mitigation_string += key.split(":")[4] + ":" + key.split(":")[5] + " (Average: " + (average / value.length).toFixed(2) + ")\n"
              // }
            }
          }

          if (mitigation_string === '') {
            mitigation_string = "NO MITIGATION FOUND"
          }

          element.records.forEach(record => {
            if (record.cpe === cpe) {
              record.mitigate = mitigation_string
            }
          })
        } else {
          element.records.forEach(record => {
            if (record.cpe === cpe) {
              record.mitigate = "NO MITIGATION FOUND"
            }
          })
        }
      }
    },
    async getCategory(id) {
      this.category_id = id
      var element = this
      const res = await axios.get(`${API_ROOT_URL}:${API_PORT}/api/cve_categories`, this.config)
      if (res) {
        element.category = res.data[id]
        Object.values(res.data[id].affected_records).forEach(record => {
          Object.values(record.cpe_uris).forEach(cpe => {
            let tmp = {
              id: record._id,
              score: record._base_metric_v3.baseScore,
              product: cpe._product + ":" + cpe._version,
              mitigate: '',
              cpe: cpe.cpe_uri
            }
            let found = false
            element.records.forEach(elem => {
              if (tmp.id === elem.id && tmp.product === elem.product) {
                found = true
              }
            })
            if (!found) {
              element.records.push(tmp)
            }

            // console.log(element.records.find(rec => {
            //   rec['id'] === tmp['id']
            // }));
            // element.records.push(tmp)

            // if (element.records.find(rec => {
            //   rec.id === tmp.id
            // }) === undefined) {
            //   element.records.push(tmp)

            // } else {
            //   console.log("SKIP");
            // }
          })
        })
      }
    }
  }
};
</script>
