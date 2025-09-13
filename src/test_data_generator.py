import numpy as np
import pandas as pd
import os
import time
import threading
import random
from datetime import datetime, timedelta
from pathlib import Path
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestDataGenerator:
    """Generate realistic test data for ransomware detection system"""
    
    def __init__(self, output_dir="test_data"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Define ransomware families and their characteristics
        self.ransomware_families = {
            'WannaCry': {
                'file_ops_rate': (100, 300),
                'cpu_usage': (70, 95),
                'memory_usage': (60, 85),
                'suspicious_extensions': ['.WNCRY', '.wcry'],
                'network_activity': (5, 15)
            },
            'Locky': {
                'file_ops_rate': (80, 250),
                'cpu_usage': (60, 90),
                'memory_usage': (50, 80),
                'suspicious_extensions': ['.locky', '.thor'],
                'network_activity': (3, 10)
            },
            'CryptoLocker': {
                'file_ops_rate': (120, 400),
                'cpu_usage': (80, 100),
                'memory_usage': (70, 95),
                'suspicious_extensions': ['.encrypted', '.locked'],
                'network_activity': (8, 20)
            },
            'Cerber': {
                'file_ops_rate': (90, 280),
                'cpu_usage': (65, 85),
                'memory_usage': (55, 75),
                'suspicious_extensions': ['.cerber', '.cerber2'],
                'network_activity': (4, 12)
            },
            'Petya': {
                'file_ops_rate': (150, 500),
                'cpu_usage': (85, 100),
                'memory_usage': (75, 95),
                'suspicious_extensions': ['.petya', '.red'],
                'network_activity': (10, 25)
            }
        }
        
        # Normal system activities
        self.normal_activities = {
            'file_backup': {
                'file_ops_rate': (20, 80),
                'cpu_usage': (30, 60),
                'memory_usage': (40, 70),
                'duration_minutes': (10, 30)
            },
            'software_install': {
                'file_ops_rate': (40, 120),
                'cpu_usage': (50, 80),
                'memory_usage': (45, 75),
                'duration_minutes': (5, 20)
            },
            'system_scan': {
                'file_ops_rate': (60, 150),
                'cpu_usage': (70, 90),
                'memory_usage': (60, 80),
                'duration_minutes': (15, 60)
            },
            'idle': {
                'file_ops_rate': (0, 5),
                'cpu_usage': (5, 25),
                'memory_usage': (20, 40),
                'duration_minutes': (30, 120)
            }
        }
        
    def generate_mixed_dataset(self, total_samples=10000, ransomware_ratio=0.3):
        """Generate a mixed dataset with both normal and ransomware samples"""
        all_data = []
        
        ransomware_samples = int(total_samples * ransomware_ratio)
        normal_samples = total_samples - ransomware_samples
        
        logger.info(f"Generating {ransomware_samples} ransomware samples...")
        
        # Generate ransomware samples
        for _ in range(ransomware_samples):
            family = random.choice(list(self.ransomware_families.keys()))
            duration = random.randint(2, 15)  # 2-15 minutes of activity
            samples = self.generate_ransomware_sample(family, duration, samples_per_minute=1)
            all_data.extend(samples)
            
        logger.info(f"Generating {normal_samples} normal samples...")
        
        # Generate normal samples
        for _ in range(normal_samples):
            activity = random.choice(list(self.normal_activities.keys()))
            duration = random.randint(5, 30)  # 5-30 minutes of activity
            samples = self.generate_normal_sample(activity, duration, samples_per_minute=1)
            all_data.extend(samples)
            
        # Shuffle the data
        random.shuffle(all_data)
        
        return all_data
        
    def generate_real_time_scenario(self, scenario_type="mixed", duration_minutes=60):
        """Generate real-time scenario data"""
        scenarios = {
            "normal_day": self._generate_normal_day_scenario,
            "ransomware_attack": self._generate_attack_scenario,
            "mixed": self._generate_mixed_scenario,
            "escalating_threat": self._generate_escalating_scenario
        }
        
        if scenario_type not in scenarios:
            raise ValueError(f"Unknown scenario type: {scenario_type}")
            
        return scenarios[scenario_type](duration_minutes)
        
    def _generate_normal_day_scenario(self, duration_minutes):
        """Generate a normal day with typical system activities"""
        data = []
        current_time = datetime.now()
        
        # Simulate a day with different activities
        activities = [
            ("idle", 15),
            ("software_install", 10),
            ("idle", 20),
            ("file_backup", 25),
            ("system_scan", 45),
            ("idle", duration_minutes - 115)
        ]
        
        for activity, minutes in activities:
            if minutes > 0:
                activity_data = self.generate_normal_sample(
                    activity, 
                    duration_minutes=minutes,
                    samples_per_minute=1
                )
                # Adjust timestamps
                for i, sample in enumerate(activity_data):
                    sample['timestamp'] = current_time + timedelta(minutes=i)
                    
                data.extend(activity_data)
                current_time += timedelta(minutes=minutes)
                
        return data
        
    def _generate_attack_scenario(self, duration_minutes):
        """Generate a ransomware attack scenario"""
        data = []
        current_time = datetime.now()
        
        # Start with normal activity
        normal_duration = duration_minutes // 3
        normal_data = self.generate_normal_sample(
            "idle", 
            duration_minutes=normal_duration,
            samples_per_minute=1
        )
        
        for i, sample in enumerate(normal_data):
            sample['timestamp'] = current_time + timedelta(minutes=i)
        data.extend(normal_data)
        current_time += timedelta(minutes=normal_duration)
        
        # Ransomware attack
        attack_duration = duration_minutes - normal_duration
        family = random.choice(list(self.ransomware_families.keys()))
        attack_data = self.generate_ransomware_sample(
            family,
            duration_minutes=attack_duration,
            samples_per_minute=1
        )
        
        for i, sample in enumerate(attack_data):
            sample['timestamp'] = current_time + timedelta(minutes=i)
        data.extend(attack_data)
        
        return data
        
    def _generate_mixed_scenario(self, duration_minutes):
        """Generate a mixed scenario with multiple activities"""
        data = []
        current_time = datetime.now()
        remaining_minutes = duration_minutes
        
        while remaining_minutes > 0:
            # Randomly choose activity type
            if random.random() < 0.2:  # 20% chance of ransomware
                family = random.choice(list(self.ransomware_families.keys()))
                activity_duration = min(random.randint(3, 10), remaining_minutes)
                activity_data = self.generate_ransomware_sample(
                    family,
                    duration_minutes=activity_duration,
                    samples_per_minute=1
                )
            else:
                activity = random.choice(list(self.normal_activities.keys()))
                activity_duration = min(random.randint(5, 20), remaining_minutes)
                activity_data = self.generate_normal_sample(
                    activity,
                    duration_minutes=activity_duration,
                    samples_per_minute=1
                )
                
            # Adjust timestamps
            for i, sample in enumerate(activity_data):
                sample['timestamp'] = current_time + timedelta(minutes=i)
                
            data.extend(activity_data)
            current_time += timedelta(minutes=activity_duration)
            remaining_minutes -= activity_duration
            
        return data
        
    def _generate_escalating_scenario(self, duration_minutes):
        """Generate an escalating threat scenario"""
        data = []
        current_time = datetime.now()
        
        # Phase 1: Normal activity (40% of time)
        phase1_duration = int(duration_minutes * 0.4)
        phase1_data = self.generate_normal_sample(
            "idle",
            duration_minutes=phase1_duration,
            samples_per_minute=1
        )
        
        for i, sample in enumerate(phase1_data):
            sample['timestamp'] = current_time + timedelta(minutes=i)
        data.extend(phase1_data)
        current_time += timedelta(minutes=phase1_duration)
        
        # Phase 2: Suspicious activity (30% of time)
        phase2_duration = int(duration_minutes * 0.3)
        phase2_data = self.generate_normal_sample(
            "system_scan",  # High activity that might look suspicious
            duration_minutes=phase2_duration,
            samples_per_minute=1
        )
        
        # Modify some samples to make them more suspicious
        for i, sample in enumerate(phase2_data):
            sample['timestamp'] = current_time + timedelta(minutes=i)
            # Add some suspicious characteristics
            if random.random() < 0.3:
                sample['suspicious_extensions'] = random.randint(1, 3)
                sample['file_ops_per_minute'] *= 1.5
                
        data.extend(phase2_data)
        current_time += timedelta(minutes=phase2_duration)
        
        # Phase 3: Full ransomware attack (remaining time)
        phase3_duration = duration_minutes - phase1_duration - phase2_duration
        family = random.choice(list(self.ransomware_families.keys()))
        phase3_data = self.generate_ransomware_sample(
            family,
            duration_minutes=phase3_duration,
            samples_per_minute=1
        )
        
        for i, sample in enumerate(phase3_data):
            sample['timestamp'] = current_time + timedelta(minutes=i)
        data.extend(phase3_data)
        
        return data
        
    def save_dataset(self, data, filename):
        """Save dataset to CSV and JSON formats"""
        df = pd.DataFrame(data)
        
        # Save as CSV
        csv_path = os.path.join(self.output_dir, f"{filename}.csv")
        df.to_csv(csv_path, index=False)
        
        # Save as JSON
        json_path = os.path.join(self.output_dir, f"{filename}.json")
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
            
        logger.info(f"Dataset saved: {csv_path} ({len(data)} samples)")
        return csv_path, json_path
        
    def create_training_dataset(self):
        """Create a comprehensive training dataset"""
        logger.info("Creating comprehensive training dataset...")
        
        # Generate base dataset
        training_data = self.generate_mixed_dataset(
            total_samples=5000,
            ransomware_ratio=0.3
        )
        
        # Add specific family samples
        for family in self.ransomware_families.keys():
            family_data = self.generate_ransomware_sample(
                family,
                duration_minutes=30,
                samples_per_minute=2
            )
            training_data.extend(family_data)
            
        # Add specific normal activity samples
        for activity in self.normal_activities.keys():
            activity_data = self.generate_normal_sample(
                activity,
                duration_minutes=20,
                samples_per_minute=2
            )
            training_data.extend(activity_data)
            
        # Shuffle and save
        random.shuffle(training_data)
        return self.save_dataset(training_data, "training_dataset")
        
    def create_test_scenarios(self):
        """Create various test scenarios"""
        scenarios = {
            "normal_day": self.generate_real_time_scenario("normal_day", 120),
            "ransomware_attack": self.generate_real_time_scenario("ransomware_attack", 90),
            "mixed_activity": self.generate_real_time_scenario("mixed", 180),
            "escalating_threat": self.generate_real_time_scenario("escalating_threat", 150)
        }
        
        scenario_files = {}
        for name, data in scenarios.items():
            csv_path, json_path = self.save_dataset(data, f"scenario_{name}")
            scenario_files[name] = {
                'csv': csv_path,
                'json': json_path,
                'samples': len(data)
            }
            
        return scenario_files
        
    def generate_live_stream(self, scenario_type="mixed", callback=None):
        """Generate live data stream for real-time testing"""
        logger.info(f"Starting live data stream: {scenario_type}")
        
        scenario_data = self.generate_real_time_scenario(scenario_type, 60)
        
        for i, sample in enumerate(scenario_data):
            if callback:
                callback(sample, i, len(scenario_data))
            else:
                print(f"Sample {i+1}/{len(scenario_data)}: Risk={sample.get('label', 0)}")
                
            time.sleep(5)  # 5-second intervals
            
        logger.info("Live stream completed")
        
    def create_feature_analysis_data(self):
        """Create data specifically for feature importance analysis"""
        analysis_data = []
        
        # Create samples with varying individual features
        base_sample = {
            'file_ops_per_minute': 10,
            'unique_extensions_accessed': 5,
            'suspicious_extensions': 0,
            'process_cpu_mean': 20,
            'process_cpu_max': 30,
            'process_memory_mean': 25,
            'process_memory_max': 35,
            'active_processes': 30,
            'network_connections': 3,
            'file_creation_rate': 5,
            'file_deletion_rate': 2,
            'file_modification_rate': 8,
            'label': 0
        }
        
        # Vary each feature individually
        features_to_vary = [
            ('file_ops_per_minute', [10, 50, 100, 200, 400]),
            ('suspicious_extensions', [0, 1, 3, 5, 10]),
            ('process_cpu_max', [30, 50, 70, 85, 95]),
            ('file_modification_rate', [8, 30, 80, 150, 300])
        ]
        
        for feature_name, values in features_to_vary:
            for value in values:
                sample = base_sample.copy()
                sample[feature_name] = value
                sample['timestamp'] = datetime.now()
                sample['family'] = f'feature_test_{feature_name}'
                # Label as ransomware if feature value is high
                sample['label'] = 1 if value > values[len(values)//2] else 0
                analysis_data.append(sample)
                
        return self.save_dataset(analysis_data, "feature_analysis")

    def generate_normal_sample(self, activity_type, duration_minutes=10, samples_per_minute=12):
        """Generate normal system activity data"""
        activity = self.normal_activities[activity_type]
        total_samples = duration_minutes * samples_per_minute
        
        data = []
        start_time = datetime.now()
        
        for i in range(total_samples):
            timestamp = start_time + timedelta(seconds=i * (60 / samples_per_minute))
            
            sample = {
                'timestamp': timestamp,
                'file_ops_per_minute': np.random.randint(
                    activity['file_ops_rate'][0],
                    activity['file_ops_rate'][1]
                ),
                'unique_extensions_accessed': np.random.randint(2, 10),
                'suspicious_extensions': 0,  # Normal activities don't create suspicious files
                'process_cpu_mean': np.random.uniform(
                    activity['cpu_usage'][0],
                    activity['cpu_usage'][1]
                ),
                'process_cpu_max': np.random.uniform(
                    activity['cpu_usage'][0] + 5,
                    min(100, activity['cpu_usage'][1] + 10)
                ),
                'process_memory_mean': np.random.uniform(
                    activity['memory_usage'][0],
                    activity['memory_usage'][1]
                ),
                'process_memory_max': np.random.uniform(
                    activity['memory_usage'][0] + 5,
                    min(100, activity['memory_usage'][1] + 10)
                ),
                'active_processes': np.random.randint(20, 50),
                'network_connections': np.random.randint(2, 8),
                'file_creation_rate': np.random.randint(0, 15),
                'file_deletion_rate': np.random.randint(0, 5),
                'file_modification_rate': np.random.randint(
                    activity['file_ops_rate'][0] // 2,
                    activity['file_ops_rate'][1] // 2
                ),
                'label': 0,  # Normal
                'family': activity_type
            }
            
            data.append(sample)
            
        return data
        
    def generate_ransomware_sample(self, family_name, duration_minutes=10, samples_per_minute=12):
        """Generate ransomware activity data"""
        family = self.ransomware_families[family_name]
        total_samples = duration_minutes * samples_per_minute
        
        data = []
        start_time = datetime.now()
        
        for i in range(total_samples):
            timestamp = start_time + timedelta(seconds=i * (60 / samples_per_minute))
            
            # Simulate escalating ransomware activity
            escalation_factor = min(1.0, i / (total_samples * 0.3))  # Ramp up over first 30%
            
            sample = {
                'timestamp': timestamp,
                'file_ops_per_minute': np.random.randint(
                    int(family['file_ops_rate'][0] * (1 + escalation_factor)),
                    int(family['file_ops_rate'][1] * (1 + escalation_factor))
                ),
                'unique_extensions_accessed': np.random.randint(5, 25),
                'suspicious_extensions': np.random.randint(1, len(family['suspicious_extensions']) + 3),
                'process_cpu_mean': np.random.uniform(
                    family['cpu_usage'][0],
                    family['cpu_usage'][1]
                ),
                'process_cpu_max': np.random.uniform(
                    family['cpu_usage'][0] + 10,
                    min(100, family['cpu_usage'][1] + 20)
                ),
                'process_memory_mean': np.random.uniform(
                    family['memory_usage'][0],
                    family['memory_usage'][1]
                ),
                'process_memory_max': np.random.uniform(
                    family['memory_usage'][0] + 10,
                    min(100, family['memory_usage'][1] + 15)
                ),
                'active_processes': np.random.randint(40, 80),
                'network_connections': np.random.randint(
                    family['network_activity'][0],
                    family['network_activity'][1]
                ),
                'file_creation_rate': np.random.randint(10, 50),
                'file_deletion_rate': np.random.randint(5, 30),
                'file_modification_rate': np.random.randint(
                    int(family['file_ops_rate'][0] * 0.8),
                    int(family['file_ops_rate'][1] * 1.2)
                ),
                'label': 1,  # Ransomware
                'family': family_name
            }
            
            data.append(sample)
            
        return data

def main():
    """Main function to generate all test data"""
    generator = TestDataGenerator()
    
    print("🔧 Generating comprehensive test dataset...")
    
    # Create training dataset
    training_files = generator.create_training_dataset()
    print(f"✅ Training dataset created: {training_files[0]}")
    
    # Create test scenarios
    scenario_files = generator.create_test_scenarios()
    print("✅ Test scenarios created:")
    for name, files in scenario_files.items():
        print(f"   - {name}: {files['samples']} samples")
        
    # Create feature analysis data
    feature_files = generator.create_feature_analysis_data()
    print(f"✅ Feature analysis dataset created: {feature_files[0]}")
    
    print(f"\n📁 All files saved in: {generator.output_dir}/")
    print("🎯 Ready for testing and training!")
    
    # Optionally start live stream demo
    response = input("\nStart live data stream demo? (y/n): ")
    if response.lower() == 'y':
        def stream_callback(sample, index, total):
            risk_level = "HIGH" if sample['label'] == 1 else "LOW"
            print(f"[{index+1:3d}/{total}] {sample['timestamp'].strftime('%H:%M:%S')} - "
                  f"Risk: {risk_level} - Family: {sample['family']}")
                  
        generator.generate_live_stream("escalating_threat", stream_callback)

if __name__ == "__main__":
    main()
    