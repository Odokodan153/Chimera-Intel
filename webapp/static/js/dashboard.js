// This file is located at webapp/static/js/dashboard.js

document.addEventListener("DOMContentLoaded", function() {
    const loadingEl = document.getElementById("loading");
    const sentimentChartEl = document.getElementById("sentiment-chart");
    const seoChartEl = document.getElementById("seo-chart");
    const kpiChartEl = document.getElementById("kpi-chart");
    const velocityChartEl = document.getElementById("velocity-chart");
    const topicChartEl = document.getElementById("topic-chart");

    // Fetch data from the API
    fetch(`/api/data/${PROJECT_NAME}`)
        .then(response => response.json())
        .then(data => {
            loadingEl.style.display = "none";
            
            if (data.error) {
                loadingEl.innerText = `Error: ${data.error}`;
                loadingEl.style.display = "block";
                return;
            }

            const charts = data.charts;
            let chartsFound = 0; // Keep track of rendered charts

            // Render KPI Chart
            if (charts.traffic_kpis && charts.traffic_kpis.data) {
                Plotly.newPlot(
                    kpiChartEl, 
                    charts.traffic_kpis.data, 
                    charts.traffic_kpis.layout
                );
                kpiChartEl.style.display = "block";
                chartsFound++;
            }

            // Render Sentiment Chart
            if (charts.sentiment && charts.sentiment.data) {
                Plotly.newPlot(
                    sentimentChartEl, 
                    charts.sentiment.data, 
                    charts.sentiment.layout
                );
                sentimentChartEl.style.display = "block";
                chartsFound++;
            }

            // Render SEO Keyword Chart
            if (charts.seo_keywords && charts.seo_keywords.data) {
                Plotly.newPlot(
                    seoChartEl, 
                    charts.seo_keywords.data, 
                    charts.seo_keywords.layout
                );
                seoChartEl.style.display = "block";
                chartsFound++;
            }

            // Render Velocity Chart
            if (charts.content_velocity && charts.content_velocity.data) {
                Plotly.newPlot(
                    velocityChartEl, 
                    charts.content_velocity.data, 
                    charts.content_velocity.layout
                );
                velocityChartEl.style.display = "block";
                chartsFound++;
            }
            
            // Render Topic Chart
            if (charts.topic_coverage && charts.topic_coverage.data) {
                Plotly.newPlot(
                    topicChartEl, 
                    charts.topic_coverage.data, 
                    charts.topic_coverage.layout
                );
                topicChartEl.style.display = "block";
                chartsFound++;
            }
            
            // Show message if no data was found at all
            if (chartsFound === 0) {
                 loadingEl.innerText = "No dashboard data found for this target.";
                 loadingEl.style.display = "block";
            }

        })
        .catch(error => {
            loadingEl.innerText = `Failed to load chart data: ${error}`;
            loadingEl.style.display = "block";
            console.error("Error fetching dashboard data:", error);
        });
});