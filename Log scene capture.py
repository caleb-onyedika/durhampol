#!/usr/bin/env python
# coding: utf-8

# In[1]:


import csv
import datetime

def log_entry():
    print("Welcome to the Digital Scene Logging System")
    print("Please enter the following details:")

    date = input("Date (YYYY-MM-DD): ")
    time = input("Time (HH:MM): ")
    name = input("Name: ")
    reason = input("Reason for Entry: ")

    entry = {
        "Date": date,
        "Time": time,
        "Name": name,
        "Reason": reason
    }
    return entry

def save_entry(entry):
    with open("scene_log.csv", "a", newline="") as csvfile:
        fieldnames = ["Date", "Time", "Name", "Reason"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:
            writer.writeheader()

        writer.writerow(entry)
    print("Entry saved successfully.")

def main():
    while True:
        entry = log_entry()
        save_entry(entry)
        another_entry = input("Would you like to log another entry? (yes/no): ")
        if another_entry.lower() != "yes":
            break

if __name__ == "__main__":
    main()


# In[ ]:




