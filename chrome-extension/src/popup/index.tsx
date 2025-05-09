import React from "react"
import ReactDOM from "react-dom/client"
import Popup from "./Popup"
import "../../styles/base.css"
import "../../styles/content.css"

const rootDivId = "popup-root"
let rootDiv = document.getElementById(rootDivId)

if (!rootDiv) {
  rootDiv = document.createElement("div")
  rootDiv.id = rootDivId
  document.body.appendChild(rootDiv)
}

const root = ReactDOM.createRoot(rootDiv as HTMLElement)

root.render(
  <React.StrictMode>
    <Popup />
  </React.StrictMode>
)
