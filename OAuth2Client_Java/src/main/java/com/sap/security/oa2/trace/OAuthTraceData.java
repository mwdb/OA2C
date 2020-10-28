package com.sap.security.oa2.trace;

import java.util.Date;

public class OAuthTraceData {
	int type;
	String description;
	byte[] data;
	String dataText;
	String dataLink;
	Date creationDate;
	int id;

	public String getDataText() {
		return dataText;
	}

	public void setDataText(String dataText) {
		this.dataText = dataText;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public String getDataLink() {
		String link = "/Teched/config?action=trace.display&data=" + id;
		return link;
	}

	public void setDataLink() {
	};
}
