<template>
  <div class="py-4 container-fluid">
    <div class="row mb-4">
      <div class="col-lg-12 position-relative z-index-2">
        <div class="row mt-4">
          <div class="col-lg-4 col-md-8 col-sm-8 mt-lg-0 mt-4">
            <mini-statistics-card :title=lastScan
              detail="Last Scan: <span class='text-success text-sm font-weight-bolder'>INSERT DATE HERE</span>" :icon="{
              }" />
          </div>
          <div class="col-lg-4 col-md-4 col-sm-4">
            <mini-statistics-card :title=totalCategories
              detail="Last Update: <span class='text-success text-sm font-weight-bolder'>INSERT DATE HERE</span>" :icon="{
              }" />
          </div>
          <div class="col-lg-4 col-md-4 col-sm-4">
            <mini-statistics-card :title=totalRecords
              detail="Last Update: <span class='text-success text-sm font-weight-bolder'>INSERT DATE HERE</span>" :icon="{
              }" />
          </div>
          <div class="row mt-4">
            <div class="col-lg-12 col-md-12">
              <div class="d-grid gap-2" style="height: 100%;">
                <button type="button" name="" id="" class="btn btn-success" style="font-size: 40px;">SCAN NOW</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12 col-md-12 mb-md-0 mb-4">
        <project-card title="Categories" description="" :headers="['vector', 'complexity', 'severity', 'score', 'size']"
          :projects="[
            {
              vector: 'NETWORK',
              complexity: 'LOW',
              severity: 'HIGH',
              score: 6.7,
              size: 20,
            }, {
              vector: 'NETWORK',
              complexity: 'LOW',
              severity: 'HIGH',
              score: 6.7,
              size: 20,
            }, {
              vector: 'NETWORK',
              complexity: 'LOW',
              severity: 'HIGH',
              score: 6.7,
              size: 20,
            }, {
              vector: 'NETWORK',
              complexity: 'LOW',
              severity: 'HIGH',
              score: 6.7,
              size: 20,
            },
          ]" />
      </div>
    </div>
  </div>
</template>
<script>
import axios from 'axios'
import MiniStatisticsCard from "./components/MiniStatisticsCard.vue";
import ProjectCard from "./components/ProjectCard.vue";
import logoXD from "@/assets/img/small-logos/logo-xd.svg";
import logoAtlassian from "@/assets/img/small-logos/logo-atlassian.svg";
import logoSlack from "@/assets/img/small-logos/logo-slack.svg";
import logoSpotify from "@/assets/img/small-logos/logo-spotify.svg";
import logoJira from "@/assets/img/small-logos/logo-jira.svg";
import logoInvision from "@/assets/img/small-logos/logo-invision.svg";
import team1 from "@/assets/img/team-1.jpg";
import team2 from "@/assets/img/team-2.jpg";
import team3 from "@/assets/img/team-3.jpg";
import team4 from "@/assets/img/team-4.jpg";
export default {
  name: "dashboard-default",
  data() {
    return {
      totalRecords: {},
      totalCategories: {},
      lastScan: {},
      logoXD,
      team1,
      team2,
      team3,
      team4,
      logoAtlassian,
      logoSlack,
      logoSpotify,
      logoJira,
      logoInvision,
    };
  },
  created() {
    this.totalRecords = { text: 'Total CVE Records', value: "-" }
    this.totalCategories = { text: 'Total Categories', value: "-" }
    this.lastScan = { text: 'Total Vulnerabilities Found', value: '-' }
    // this.getTotalRecords()
  },
  methods:
  {
    async getTotalRecords() {
      let config = {
        headers: {
          'Accept': 'application/json'
        }
      }
      const res = await axios.get('http://127.0.0.1:8000/api/cve_db/', config)
      this.totalRecords.value = res.data.size

    }
  },

  components: {
    MiniStatisticsCard,
    ProjectCard,
  },
};
</script>
